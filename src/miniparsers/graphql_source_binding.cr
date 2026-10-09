module Noir
  # Bounded, filesystem-free traversal of the supplied JS source index.
  # Supports direct SDL imports and loadFilesSync(resolve(__dirname, ...)).
  # Unsupported loaders stay definition candidates instead of server routes.
  module GraphqlSourceBinding
    extend self

    def bound?(sdl : String, mount_file : String, sources : Hash(String, String), root : String) : Bool
      pending = [mount_file]
      seen = Set(String).new
      128.times do
        file = pending.shift?
        break unless file
        next unless seen.add?(file)
        source = sources[file]?
        next unless source
        source.scan(/\b(?:from\s*|import\s*|require\s*\(\s*)['"](\.[^'"]+)['"]/) do |match|
          target = File.expand_path(match[1], File.dirname(file))
          next unless under?(target, root)
          return true if target == File.expand_path(sdl)
          [target, target + ".ts", target + ".js", target + "/index.ts", target + "/index.js"].each do |candidate|
            pending << candidate if sources.has_key?(candidate) && !seen.includes?(candidate)
          end
        end
        next unless source.includes?("loadFilesSync") && source.includes?("*.graphql")
        source.scan(/resolve\s*\(\s*__dirname\s*,\s*['"]([^'"]+)['"]\s*\)/) do |match|
          directory = File.expand_path(match[1], File.dirname(file)).rchop('/')
          return true if under?(directory, root) && File.expand_path(sdl).starts_with?(directory + "/")
        end
      end
      false
    end

    private def under?(path : String, root : String) : Bool
      base = File.expand_path(root).rchop('/')
      path == base || path.starts_with?(base + "/")
    end
  end
end
