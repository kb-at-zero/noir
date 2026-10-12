require "../javascript/nestjs"

module Analyzer::Typescript
  class Nestjs < Analyzer::Javascript::Nestjs
    analyzer_for "ts_nestjs"

    def analyze
      result = analyze_with_extensions([".ts", ".tsx"])

      # Outbound calls from RESTDataSource subclasses and NestJS Fetch-DI
      # clients: cross-file pass plus node-config sources.
      begin
        outbound_sources = {} of String => String
        (get_files_by_extension(".js") + get_files_by_extension(".ts")).each do |path|
          next if path.includes?("/test/") || path.includes?(".test.") || path.includes?(".spec.")
          content = read_file_content(path)
          outbound_sources[path] = content if content.includes?("DataSource") ||
                                             content.includes?("dataSource") ||
                                             content.includes?("datasource") ||
                                             content.includes?("@Inject(")
        end
        unless outbound_sources.empty?
          config_sources = [] of String
          ["config/default.js", "config/production.js", "config/default.ts",
           "config/production.ts", "config/default.json", "config/production.json"].each do |rel|
            get_files_by_relative_path(rel).each { |f| config_sources << read_file_content(f) }
          end
          result.concat(Noir::JSOutboundExtractor.extract(outbound_sources, config_sources))
        end
      rescue e
        logger.debug "outbound extraction failed: #{e.message}"
      end

      result
    end

    protected def owns_source?(content : String) : Bool
      !content.includes?(MIDWAY_IMPORT)
    end
  end
end
