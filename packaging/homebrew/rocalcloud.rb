class Rocalcloud < Formula
  desc "Local, in-memory cloud API emulator with GUI, character town, and LLM agents"
  homepage "https://github.com/jinyounghwa/server_go"
  license "Apache-2.0"
  # Update version, url, and sha256 when cutting a tagged GitHub release.
  version "0.1.4"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-aarch64-apple-darwin.tar.gz"
      sha256 "86adf68e89a92ae02375361ad4f7a06ad497bbea94e9f752cbc8722e1b9cbab9"
    else
      url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-x86_64-apple-darwin.tar.gz"
      sha256 "7a70c239d944174b0291a0236634b3c0cf107d0281055e434119c34a22431391"
    end
  end

  on_linux do
    url "https://github.com/jinyounghwa/server_go/releases/download/v#{version}/rocalcloud-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "52b7676c2a28d37fbff05129085570c28ccf66cf5b7292b0cd5bc9b9b486ee0a"
  end

  def install
    bin.install "rocalcloud"
  end

  test do
    assert_match "rocalcloud", shell_output("#{bin}/rocalcloud --help 2>&1", 1)
  end
end
