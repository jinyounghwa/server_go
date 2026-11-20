class Rocalcloud < Formula
  desc "Local, in-memory cloud API emulator with GUI, character town, and LLM agents"
  homepage "https://github.com/jinyounghwa/server_go"
  license "Apache-2.0"
  # Update version, url, and sha256 when cutting a tagged GitHub release.
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_ARM64_SHA256"
    else
      url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_X86_64_SHA256"
    end
  end

  on_linux do
    url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "REPLACE_WITH_LINUX_SHA256"
  end

  def install
    bin.install "rocalcloud"
  end

  test do
    assert_match "rocalcloud", shell_output("#{bin}/rocalcloud --help 2>&1", 1)
  end
end
