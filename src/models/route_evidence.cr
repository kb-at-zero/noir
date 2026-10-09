require "json"
require "yaml"

# Source facts, never deployment facts. Unknown is deliberately the default:
# an analyzer must provide evidence before claiming registration or a mount.
struct RouteEvidence
  include JSON::Serializable
  include YAML::Serializable

  property entrypoint : String = ""
  property handler : String = ""
  property path_resolution : String = "resolved"
  property path_expression : String = ""
  property candidate_identity : String = ""
  property registration_status : String = "unknown"
  property mount_expression : String = ""
  property mount_file : String = ""
  property mount_line : Int32? = nil
  property issues : Array(String) = [] of String
  property definition_only : Bool = false

  def initialize
  end

  def detached_copy : RouteEvidence
    copy = self
    copy.issues = issues.dup
    copy
  end

  def scope : String
    {entrypoint, mount_expression, mount_file, mount_line.to_s, candidate_identity}.join("|")
  end
end
