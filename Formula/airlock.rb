# typed: false
# frozen_string_literal: true

# Formula for Airlock (bonjoski/airlock)
# Zero-trust workstation sandbox for untrusted package installs & agentic AI loops.
class Airlock < Formula
  desc "Zero-trust workstation sandbox for untrusted package installs & agentic loops"
  homepage "https://github.com/bonjoski/airlock"
  url "https://github.com/bonjoski/airlock/archive/refs/tags/v0.6.0.tar.gz"
  sha256 "PLACEHOLDER_SOURCE_SHA256"
  license "MIT"
  head "https://github.com/bonjoski/airlock.git", branch: "main"

  depends_on "go" => :build

  on_linux do
    depends_on "bubblewrap"
  end

  def install
    ldflags = %W[
      -s -w
      -X github.com/bonjoski/airlock/pkg/version.Version=#{version}
      -X github.com/bonjoski/airlock/pkg/version.Commit=brew
      -X github.com/bonjoski/airlock/pkg/version.BuildTime=#{time.iso8601}
    ]

    system "go", "build", *std_go_args(ldflags: ldflags.join(" ")), "./cmd/airlock"
    system "go", "build", *std_go_args(output: bin/"airlock-mcp", ldflags: ldflags.join(" ")), "./cmd/airlock-mcp"
  end

  def caveats
    <<~EOS
      Airlock has been installed!

      To configure transparent shims for package managers (npm, pip, cargo, uv, bun):
        airlock shim install

      Ensure your PATH includes the shim directory:
        export PATH="$HOME/.airlock/bin:$PATH"

      Quick test:
        airlock run -- echo "Sandbox active"
    EOS
  end

  test do
    assert_match "Airlock version", shell_output("#{bin}/airlock version")
    assert_match "Sandbox active", shell_output("#{bin}/airlock run -- echo 'Sandbox active'")
  end
end
