class Rocalcloud < Formula
  desc "Local, in-memory cloud API emulator with GUI, character town, and LLM agents"
  homepage "https://github.com/jinyounghwa/server_go"
  license "Apache-2.0"
  # Update version, url, and sha256 when cutting a tagged GitHub release.
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-aarch64-apple-darwin.tar.gz"
      sha256 "9c0b8f621f1fceb157f57ddfb17fdb6b390714fe3ca59ab8f73c42c0c70d34ea"
    else
      url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-x86_64-apple-darwin.tar.gz"
      sha256 "9a3329b1aca3d782d43e12cf09dae948b68a35472d224a4dfb5d15b9fecb6c6d"
    end
  end

  on_linux do
    url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "6b070cfc30b2b48682dccf2f339f5c81dc147607e35511c610d91440e115d961"
  end

  def install
    bin.install "rocalcloud"
  end

  test do
    assert_match "rocalcloud", shell_output("#{bin}/rocalcloud --help 2>&1", 1)
  end
end
