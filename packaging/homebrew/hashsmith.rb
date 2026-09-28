# Homebrew formula for Hashsmith.
#
# This file lives here so it is versioned alongside the release workflow that
# produces the binaries it points at. Homebrew reads formulae from a tap
# repository, so releasing means copying this file into the tap
# (s4l1hs/homebrew-hashsmith) with the new version and checksums filled in.
#
# It installs a PREBUILT binary. The previous formula built from source, which
# made `brew install` require a Go toolchain and take minutes; the release
# workflow now publishes binaries for exactly these platforms, so there is no
# reason to compile on the user's machine.
#
# To update for a release:
#   1. Set `version`.
#   2. Replace each sha256 with the value from the release's SHA256SUMS.
class Hashsmith < Formula
  desc "Terminal-first toolkit for encoding, decoding, hashing, cracking and identification"
  homepage "https://github.com/s4l1hs/Hashsmith"
  version "0.0.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/s4l1hs/Hashsmith/releases/download/v#{version}/hashsmith-#{version}-darwin-arm64"
      sha256 "REPLACE_WITH_DARWIN_ARM64_SHA256"
    end
    on_intel do
      url "https://github.com/s4l1hs/Hashsmith/releases/download/v#{version}/hashsmith-#{version}-darwin-amd64"
      sha256 "REPLACE_WITH_DARWIN_AMD64_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/s4l1hs/Hashsmith/releases/download/v#{version}/hashsmith-#{version}-linux-arm64"
      sha256 "REPLACE_WITH_LINUX_ARM64_SHA256"
    end
    on_intel do
      url "https://github.com/s4l1hs/Hashsmith/releases/download/v#{version}/hashsmith-#{version}-linux-amd64"
      sha256 "REPLACE_WITH_LINUX_AMD64_SHA256"
    end
  end

  def install
    bin.install Dir["hashsmith-*"].first => "hashsmith"
    generate_completions_from_executable(bin/"hashsmith", "completion", shells: [:bash, :zsh, :fish])
  end

  test do
    # The binary carries its own known-answer vectors, so the test can verify
    # that this build computes correct digests rather than merely starting.
    assert_match "vectors passed", shell_output("#{bin}/hashsmith -N selftest")
    assert_match version.to_s, shell_output("#{bin}/hashsmith --version")
    assert_match "password",
      shell_output("#{bin}/hashsmith -N crack -t md5 5f4dcc3b5aa765d61d8327deb882cf99")
  end
end
