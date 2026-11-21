class Rocalcloud < Formula
  desc "Local, in-memory cloud API emulator with GUI, character town, and LLM agents"
  homepage "https://github.com/jinyounghwa/server_go"
  license "Apache-2.0"
  # Update version, url, and sha256 when cutting a tagged GitHub release.
  version "0.1.3"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-aarch64-apple-darwin.tar.gz"
      sha256 "318ef4fbf2b5ced468542809840d5901ee546a3a1487ae8ab19b7f1fb726ae75"
    else
      url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-x86_64-apple-darwin.tar.gz"
      sha256 "0d8dc63008be8d242b5459ac10d1e3e40b8fb7cd130d0bfbcd86e584d3a97e94"
    end
  end

  on_linux do
    url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "0f01ecb407d9868b19170d42c13889db0ea354e63c2a2eea106bde56528f8d61"
  end

  def install
    bin.install "rocalcloud"
  end

  test do
    assert_match "rocalcloud", shell_output("#{bin}/rocalcloud --help 2>&1", 1)
  end
end
