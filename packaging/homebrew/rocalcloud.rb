class Rocalcloud < Formula
  desc "Local, in-memory cloud API emulator with GUI, character town, and LLM agents"
  homepage "https://github.com/jinyounghwa/server_go"
  license "Apache-2.0"
  # Update version, url, and sha256 when cutting a tagged GitHub release.
  version "0.1.2"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-aarch64-apple-darwin.tar.gz"
      sha256 "a5478c1f9bf96197cda49a78f29c1cfc53a1134acc0846f85f933de067c4e472"
    else
      url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-x86_64-apple-darwin.tar.gz"
      sha256 "bae2c8eb6b76537b5f41dafa6677bbb25ffcf2a66eac0a8c4dba4b60c8f1410a"
    end
  end

  on_linux do
    url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "f24138440fbba5793d628979fd5a423b1940d34c13574299655202af9cf726a2"
  end

  def install
    bin.install "rocalcloud"
  end

  test do
    assert_match "rocalcloud", shell_output("#{bin}/rocalcloud --help 2>&1", 1)
  end
end
