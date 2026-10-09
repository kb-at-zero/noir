require "../utils/url_path"
require "../ext/tree_sitter/tree_sitter"

module Noir
  # Resolves a deliberately small, static Apollo Server mount shape. An
  # unresolved template is never guessed: callers keep /graphql and can
  # reconcile the mount from runtime configuration instead.
  module JSConfigPathResolver
    extend self

    MOUNT            = /\.applyMiddleware\s*\(\s*\{[^}]{0,1000}\bpath\s*:\s*(`[^`]+`|'[^']+'|"[^"]+")/m
    CONFIG_REFERENCE = /\A\$\{config\.get(?:<[^>]+>)?\(\s*['"]([A-Za-z_][A-Za-z_0-9]*)['"]\s*\)\}(\/[^`$]*)\z/
    CONFIG_ENTRY     = /\b([A-Za-z_][A-Za-z_0-9]*)\s*:\s*['"]([^'"]+)['"]/

    def apollo_mount_expression(source : String) : String?
      apollo_mount_expressions(source).first?
    end

    def apollo_mount_expressions(source : String) : Array(String)
      expressions = [] of String
      TreeSitter.parse_javascript(source) do |root|
        TreeSitter.walk(root) do |node|
          next unless TreeSitter.node_type(node) == "call_expression"
          fn = TreeSitter.field(node, "function")
          args = TreeSitter.field(node, "arguments")
          next unless fn && args && TreeSitter.node_text(fn, source).ends_with?(".applyMiddleware")
          object = TreeSitter.first_named_child(args)
          next unless object && TreeSitter.node_type(object) == "object"
          found = false
          TreeSitter.each_named_child(object) do |pair|
            key = TreeSitter.field(pair, "key")
            value = TreeSitter.field(pair, "value")
            next unless key && value && TreeSitter.node_text(key, source).strip('"').strip('\'') == "path"
            text = TreeSitter.node_text(value, source)
            expressions << (%w[string template_string].includes?(TreeSitter.node_type(value)) ? text[1...-1] : text)
            found = true
          end
          expressions << "/graphql" unless found
        end
      end
      expressions.uniq
    end

    def config_key(expression : String) : String?
      expression.match(CONFIG_REFERENCE).try(&.[1])
    end

    def config_value(source : String, key : String) : String?
      source.scan(CONFIG_ENTRY) do |match|
        return match[2] if match[1] == key
      end
      nil
    end

    def resolve(expression : String, config_value : String? = nil) : String?
      return expression if valid_path?(expression)
      match = expression.match(CONFIG_REFERENCE)
      return unless match && config_value
      return unless valid_path?(config_value)
      suffix = match[2]
      return unless valid_path?(suffix)
      URLPath.join(config_value, suffix)
    end

    def resolve_with_configs(expression : String, config_sources : Array(String)) : String?
      key = config_key(expression)
      return resolve(expression) unless key
      values = config_sources.compact_map { |source| config_value(source, key) }.uniq
      return unless values.size == 1
      resolve(expression, values.first)
    end

    private def valid_path?(path : String) : Bool
      path.starts_with?('/') && !path.starts_with?("//") &&
        !path.includes?('?') && !path.includes?('#') &&
        !path.matches?(/[\x00-\x1f\\]/)
    end
  end
end
