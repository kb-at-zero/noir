require "../models/endpoint"
require "../models/route_evidence"
require "./js_config_path_resolver"
require "../utils/js_literal_scanner"

module Noir
  # Extracts outbound HTTP calls from Apollo RESTDataSource subclasses in
  # BFF-style TypeScript/JavaScript services, resolving their base URL from
  # node-config files and attributing each call to the GraphQL operation
  # whose resolver invokes the datasource (when statically provable).
  #
  #   class Connector extends RESTDataSourceBasic {
  #     apiPrefixConfigName = 'CONNECTION_PLATFORM_API_PREFIX'
  #     apiVersion = 'v2'
  #     async getConnectionScopes() { await this.get('/connections', ...) }
  #   }
  #   # resolver: Query: { connectionScopes: getConnectionScopes }
  #
  # Honesty rules: interpolated URLs stay expressions; unattributed calls
  # become service-level outbound records (issue: service_level).
  module JSOutboundExtractor
    extend self

    alias TS = TreeSitter
    alias Node = LibTreeSitter::TSNode

    VERBS = {"get", "post", "put", "patch", "delete", "head", "options"}

    DS_SUBCLASS = /\bextends\s+(?:[A-Za-z_$][\w$]*\.)?[A-Za-z_$\w]*RESTDataSource[A-Za-z_$\w]*\b/
    CLASS_DECL  = /class\s+([A-Za-z_$][\w$]*)\s+extends\s+(?:[A-Za-z_$][\w$]*\.)?[A-Za-z_$\w]*RESTDataSource[A-Za-z_$\w]*\s*\{/

    record ClassMeta, name : String, prefix_key : String, api_version : String
    record CallSite, datasource : String, method_name : String, http_method : String,
      url : String, dynamic : Bool, file : String, line : Int32

    def extract(sources : Hash(String, String), config_sources : Array(String)) : Array(Endpoint)
      calls = [] of CallSite
      class_meta = {} of String => ClassMeta

      sources.each do |file, content|
        next unless content.includes?("extends") && content.matches?(DS_SUBCLASS)
        collect_class_calls(file, content).each do |meta, site|
          calls << site
          class_meta[meta.name] = meta
        end
      end
      return [] of Endpoint if calls.empty?

      instances = instance_names(sources, class_meta.keys)
      endpoints = [] of Endpoint
      calls.each do |site|
        meta = class_meta[site.datasource]? || ClassMeta.new(site.datasource, "", "")
        base = config_value(config_sources, meta.prefix_key)
        url, dynamic = compose_url(base, meta.api_version, site)
        field = attribute(sources, instances, site)
        endpoints << build_endpoint(site, url, dynamic, field, meta.prefix_key, base)
      end
      endpoints
    end

    # -- datasource classes ------------------------------------------------
    # Regex + brace matching rather than tree-sitter: the TS-only `protected`
    # class-field modifier breaks the vendored JavaScript grammar, and the
    # datasource layout is regular enough to scan textually.
    private def collect_class_calls(file : String, content : String)
      found = [] of Tuple(ClassMeta, CallSite)
      content.scan(CLASS_DECL) do |cls_match|
        cls = cls_match[1]
        open_idx = cls_match.end.not_nil! - 1 # last char of match is '{'
        close_idx = JSLiteralScanner.find_matching_brace(content, open_idx)
        next unless close_idx
        body = content[open_idx + 1...close_idx]

        prefix_key = body.match(/apiPrefixConfigName\s*=\s*['"]([^'"]+)['"]/).try(&.[1]) || ""
        api_version = body.match(/apiVersion\s*=\s*['"]([^'"]+)['"]/).try(&.[1]) || ""

        # Method spans: `name(...) {` with running start offset so each
        # this.<verb>( call site attributes to the nearest enclosing method.
        methods = [] of Tuple(String, Int32, Int32)
        body.scan(/(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::[^{]+)?\{/) do |m|
          s = m.begin.not_nil!
          e = JSLiteralScanner.find_matching_brace(body, m.end.not_nil! - 1) || body.size
          methods << {m[1], s, e}
        end

        body.scan(/\bthis\s*\.\s*(#{VERBS.join("|")})(?:<(?:[^<>]|<[^<>]*>)*>)?\s*\(\s*(`[^`]*`|'[^']*'|"[^"]*")/) do |call|
          pos = call.begin.not_nil!
          owner = ""
          methods.each do |name, s, e|
            if pos > s && pos < e
              owner = name
              break
            end
          end
          url_raw = call[2]? || ""
          url = url_raw.size >= 2 ? url_raw[1..-2] : ""
          dynamic = url.includes?("${") || url.empty?
          line = content[0, cls_match.begin.not_nil! + 1 + pos].count('\n') + 1
          found << {ClassMeta.new(cls, prefix_key, api_version),
                    CallSite.new(cls, owner, call[1].upcase, url, dynamic, file, line)}
        end
      end
      found
    end

    private def enclosing_method_name(body : Node, target : Node, content : String) : String
      best = ""
      TS.walk(body) do |node|
        next unless TS.node_type(node) == "method_definition"
        name_n = TS.field(node, "name")
        body_n = TS.field(node, "body")
        next unless name_n && body_n
        if TS.node_start_row(node) <= TS.node_start_row(target) &&
           TS.node_end_row(node) >= TS.node_end_row(target)
          best = TS.node_text(name_n, content)
        end
      end
      best
    end

    private def literal_url(arg : Node, content : String) : Tuple(String, Bool)
      case TS.node_type(arg)
      when "string"
        {TS.node_text(arg, content)[1..-2], false}
      when "template_string"
        text = TS.node_text(arg, content)[1..-2]
        {text, text.includes?("${")}
      else
        {"", true}
      end
    end

    private def first_named_child(node : Node) : Node?
      result : Node? = nil
      TS.each_named_child(node) do |child|
        result = child if result.nil?
      end
      result
    end

    # -- config + URL composition ------------------------------------------
    # Local config lookup: also accepts backtick template literals, which
    # node-config repos commonly use for URL prefixes (`http://...`).
    private def config_value(config_sources : Array(String), key : String) : String
      return "" if key.empty?
      config_sources.each do |src|
        if m = src.match(/\b#{Regex.escape(key)}\s*:\s*(['"`])([^'"`\n]+)\1/)
          return m[2] unless m[2].empty?
        end
      end
      ""
    end

    private def compose_url(base : String, version : String, site : CallSite) : Tuple(String, Bool)
      url = site.url
      dynamic = site.dynamic
      unless base.empty?
        base_filled = base.gsub(":version", version).gsub(/\$\{[^}]+\}/, "")
        url = join_url(base_filled, url)
      end
      # An empty :version substitution or joined prefixes can produce
      # duplicate slashes; collapse them outside the scheme separator.
      url = url.gsub("://", "\u0000").gsub(/\/{2,}/, "/").gsub("\u0000", "://")
      {url, dynamic}
    end

    private def join_url(base : String, path : String) : String
      return path if base.empty?
      return base if path.empty?
      base.rchop('/') + "/" + path.lchop('/')
    end

    # -- attribution --------------------------------------------------------
    # Instance map: `connector: new Connector(` across the repo, plus class
    # import aliases (`import { CreatorsDataSource as ConnectorCreators }`)
    # so renamed wirings still resolve to the declaring class.
    private def instance_names(sources : Hash(String, String),
                               classes : Array(String)) : Hash(String, Array(String))
      map = {} of String => Array(String)
      known = classes.dup
      sources.each_value do |content|
        content.scan(/([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)/) do |m|
          known << m[2] if classes.includes?(m[1])
        end
      end
      classes.each do |cls|
        names = [] of String
        sources.each_value do |content|
          known.each do |cname|
            content.scan(/([A-Za-z_$][\w$]*)\s*[:=]\s*new\s+#{Regex.escape(cname)}\s*\(/) do |m|
              names << m[1]
            end
          end
        end
        map[cls] = names.uniq unless names.empty?
      end
      map
    end

    private def attribute(sources : Hash(String, String),
                          instances : Hash(String, Array(String)), site : CallSite) : String
      method = site.method_name
      return "" if method.empty?
      aliases = instances[site.datasource]? || [] of String

      sources.each do |file, content|
        next unless file.includes?("resolver") || file.includes?("graphql") ||
                    content.includes?("Query") || content.includes?("Mutation")
        # 1) named mapping: field: helperName (helper == ds method)
        content.scan(/([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?(?:function\s+)?([A-Za-z_$][\w$]*)\s*[,}\n)=]/) do |m|
          return m[1] if m[2] == method
        end
        # 2) arrow property: field: (…) => body — the body spans exactly to
        # the next arrow property. The receiver may be any property access
        # (`dataSources.connectorCreators.method(`): import-aliased classes
        # make a strict alias map unreliable, so match on the method call
        # shape with any receiver.
        arrows = [] of Tuple(String, Int32)
        content.scan(/([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?\(\s*[^)]*\)?\s*=>/) do |m|
          arrows << {m[1], m.begin.not_nil!}
        end
        method_needles = aliases.flat_map { |a| ["#{a}.#{method}(", "dataSources.#{a}.#{method}("] }
        generic_needle = "#{method}("
        arrows.each_with_index do |(field, start), i|
          span_end = i + 1 < arrows.size ? arrows[i + 1][1] : content.size
          chunk = content[start...Math.min(span_end, content.size)]
          return field if method_needles.any? { |n| chunk.includes?(n) }
        end
        # Fallback: any receiver (import-aliased datasources break the alias
        # map). Last resort — method-name collisions across datasources can
        # mis-attribute here, so it runs only when the strict pass found nothing.
        arrows.each_with_index do |(field, start), i|
          span_end = i + 1 < arrows.size ? arrows[i + 1][1] : content.size
          chunk = content[start...Math.min(span_end, content.size)]
          return field if chunk.includes?(generic_needle)
        end
      end
      ""
    end

    # -- endpoint -----------------------------------------------------------
    private def build_endpoint(site : CallSite, url : String, dynamic : Bool,
                               field : String, config_key : String, base : String) : Endpoint
      details = Details.new(PathInfo.new(site.file, site.line))
      details.technology = "outbound_call"
      evidence = RouteEvidence.new
      evidence.handler = site.method_name.empty? ? site.datasource : "#{site.datasource}.#{site.method_name}"
      evidence.entrypoint = field
      evidence.path_resolution = dynamic ? "unresolved" : "resolved"
      evidence.registration_status = "registered"
      evidence.mount_expression = config_key.empty? ? "" : "#{config_key} = #{base}"
      evidence.issues << "dynamic_url" if dynamic
      evidence.issues << "service_level" if field.empty?
      details.route_evidence = evidence
      Endpoint.new(url, site.http_method, details)
    end
  end
end
