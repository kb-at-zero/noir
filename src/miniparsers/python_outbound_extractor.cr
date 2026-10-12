require "../models/endpoint"
require "../models/route_evidence"

module Noir
  # Extracts outbound HTTP calls from Python services: httpx/requests
  # module-level calls and Client instances, with URL from literals,
  # module constants and f-string/format static prefixes. Attribution
  # walks the reverse caller graph (bare-name and self./obj. method
  # calls) up to the route handler def.
  module PythonOutboundExtractor
    extend self

    VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}

    record CallSite, func : String, verb : String, url : String, dynamic : Bool,
      file : String, line : Int32

    def extract(sources : Hash(String, String), route_handlers : Array(String)) : Array(Endpoint)
      # function table: name => [(file, start_line, end_line)]
      fns = Hash(String, Array(Tuple(String, Int32, Int32))).new { |h, k| h[k] = [] of Tuple(String, Int32, Int32) }
      consts = {} of String => String
      sources.each do |file, source|
        collect_fns(file, source, fns)
        collect_consts(file, source, consts)
      end

      callers = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
      sources.each do |file, source|
        index_callers(file, source, fns, callers)
      end

      handler_set = route_handlers.to_set
      sites = [] of CallSite
      sources.each do |file, source|
        next unless source.includes?("httpx") || source.includes?("requests")
        collect_call_sites(file, source, consts, sites)
      end
      return [] of Endpoint if sites.empty?

      endpoints = [] of Endpoint
      sites.each do |site|
        owner = attribute_up(callers, handler_set, site.func, 8)
        endpoints << build(site, owner)
      end
      endpoints
    end

    private def collect_fns(file : String, source : String, fns)
      lines = source.split("\n")
      i = 0
      while i < lines.size
        if m = lines[i].match(/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/)
          name = m[1]
          start = i
          # body until next def/class at same-or-lower indent or EOF
          j = i + 1
          while j < lines.size
            break if lines[j] =~ /^\s*(?:async\s+)?def\s|^\s*class\s/ && lines[j].size > 0
            j += 1
          end
          fns[name] << {file, start + 1, j}
          i = j
        else
          i += 1
        end
      end
    end

    private def collect_consts(file : String, source : String, consts)
      source.scan(/^([A-Z][A-Z0-9_]{2,})\s*=\s*(f?"([^"\n]*)"|\w+\s*\+\s*"([^"\n]*)")/) do |m|
        value = m[3]? || m[4]? || ""
        consts[m[1]] = value unless value.empty?
      end
    end

    private def index_callers(file : String, source : String,
                              fns : Hash(String, Array(Tuple(String, Int32, Int32))),
                              callers : Hash(String, Array(String)))
      lines = source.split("\n")
      i = 0
      while i < lines.size
        if m = lines[i].match(/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/)
          caller = m[1]
          j = i + 1
          while j < lines.size && !(lines[j] =~ /^\s*(?:async\s+)?def\s|^\s*class\s/)
            # name( or x.name( or self.name( — loose by method name
            lines[j].scan(/(?:\.|\s|^)([A-Za-z_]\w*)\s*\(/) do |cm|
              callers[cm[1]] << caller if fns.has_key?(cm[1])
            end
            j += 1
          end
          i = j
        else
          i += 1
        end
      end
    end

    private def collect_call_sites(file : String, source : String,
                                   consts : Hash(String, String), sites : Array(CallSite))
      verb_re = VERBS.join("|")
      lines = source.split("\n")
      lines.each_with_index do |line, idx|
        next if line.strip.starts_with?("#")
        # httpx.post(URL, ...) / requests.get(...) / client.get(...)
        line.scan(/\b(?:httpx|requests)\s*\.\s*(#{verb_re})\s*\(\s*([A-Za-z_][\w.]*)/) do |m|
          verb = m[1] == "request" ? "GET" : m[1].upcase
          url, dynamic = resolve_url(m[2], consts, source, line)
          sites << CallSite.new(enclosing_fn(lines, idx), verb, url, dynamic, file, idx + 1)
        end
        # httpx.stream("GET", url, ...) — first arg is the verb
        line.scan(/\bhttpx\s*\.\s*stream\s*\(\s*['"](\w+)['"]\s*,\s*([A-Za-z_][\w.]*)/) do |m|
          url, dynamic = resolve_url(m[2], consts, source, line)
          sites << CallSite.new(enclosing_fn(lines, idx), m[1].upcase, url, dynamic, file, idx + 1)
        end
      end
      sites.uniq! { |s| {s.file, s.line, s.verb} }
    end

    private def resolve_url(expr : String, consts : Hash(String, String),
                            source : String, line : String) : Tuple(String, Bool)
      if m = expr.match(/\Af?"([^"]*)"\z/)
        return {m[1], m[1].includes?("{")}
      end
      if v = consts[expr.split('.').last?]?
        return {v, false}
      end
      # f"{VAR}/path" or "{}".format: static suffix after last interpolation
      if m = line.match(/\Af?"\{[^}]*\}([^"]*)"\z/)
        return {m[1], true}
      end
      if m = line.match(/\.format\([^)]*\)/)
        # "{}/x".format(base): take suffix after {}
        if fm = line.match(/"\{\}([^"]*)"/)
          return {fm[1], true}
        end
      end
      {expr, true}
    end

    private def enclosing_fn(lines : Array(String), idx : Int32) : String
      i = idx
      while i >= 0
        if m = lines[i].match(/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/)
          return m[1]
        end
        i -= 1
      end
      ""
    end

    private def attribute_up(callers : Hash(String, Array(String)),
                             handler_set : Set(String), start : String,
                             max_depth : Int32) : String
      return "" if start.empty?
      return start if handler_set.includes?(start)
      frontier = Set{start}
      visited = Set{start}
      max_depth.times do
        next_frontier = Set(String).new
        frontier.each do |sym|
          callers[sym]?.try &.each do |caller|
            next if visited.includes?(caller)
            visited << caller
            next_frontier << caller
            return caller if handler_set.includes?(caller)
          end
        end
        frontier = next_frontier
        break if frontier.empty?
      end
      ""
    end

    private def build(site : CallSite, owner : String) : Endpoint
      details = Details.new(PathInfo.new(site.file, site.line))
      details.technology = "outbound_call"
      evidence = RouteEvidence.new
      evidence.handler = site.func.presence || "module-level"
      evidence.entrypoint = owner
      evidence.path_resolution = site.dynamic ? "unresolved" : "resolved"
      evidence.registration_status = "registered"
      evidence.issues << "dynamic_url" if site.dynamic
      evidence.issues << "service_level" if owner.empty?
      details.route_evidence = evidence
      Endpoint.new(site.url, site.verb, details)
    end
  end
end
