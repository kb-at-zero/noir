require "../../../spec_helper"
require "../../../../src/detector/detectors/go/*"

describe "Detect Go Gin" do
  options = create_test_options
  instance = Detector::Go::Gin.new options

  it "go.mod" do
    instance.detect("go.mod", "github.com/gin-gonic/gin").should be_true
  end

  it "recognizes the company API server wrapper without a direct Gin dependency" do
    instance.detect("server.go", "import api_server \"github.com/AfterShip/gopkg/api/server\"").should be_true
    instance.detect("client.go", "import \"github.com/AfterShip/gopkg/log\"").should be_false
  end
end
