# Homebrew formula for SafePaste.
#
# A formula rather than a cask, deliberately. A cask ships a prebuilt binary, which
# on macOS means notarisation and an Apple Developer subscription; a formula builds
# from the source tarball GitHub generates for every tag, and needs no certificate
# at all. The trade is a slower install and a dependency on Homebrew's Python.
#
# Install:
#   brew tap amigoun/safepaste https://github.com/amigoun/safepaste-linux
#   brew install amigoun/safepaste/safepaste
#
# This file lives at Formula/ rather than under packaging/ for one reason: that is
# where `brew tap` looks. With it anywhere else the tap succeeds and the install
# then reports no such formula, so the repository doubles as its own tap.
#
# The fully-qualified name on the second line is not decoration. Current Homebrew
# treats third-party taps as untrusted and refuses to install from them by bare
# name; naming the formula in full is how you say you meant this one.
#
# The PyObjC resources are what make the tray, the hotkey and keystroke injection
# work. Without them the CLI and the clipboard guard still function, so they are
# required rather than optional only because a partial install is more confusing
# than a larger one.
#
# Resource URLs and hashes are generated from PyPI, never written by hand. Regenerate
# with `brew update-python-resources Formula/safepaste.rb` after a dependency bump;
# scripts/sync-homebrew-resources.py does the same thing without needing Homebrew.
class Safepaste < Formula
  include Language::Python::Virtualenv

  desc "Clipboard secret-guard: redacts credentials before they can be pasted"
  homepage "https://github.com/amigoun/safepaste-linux"
  url "https://github.com/amigoun/safepaste-linux/archive/refs/tags/v0.5.1.tar.gz"
  sha256 "a833a979b42c75f5384e4794bd925f83d91c85258b4e6d47ea9c1ffa60039e1f"
  license "MIT"
  head "https://github.com/amigoun/safepaste-linux.git", branch: "main"

  depends_on "python@3.12"

  resource "regex" do
    url "https://files.pythonhosted.org/packages/20/98/04b13f1ddfb63158025291c02e03eb42fbb7acb51d091d541050eb4e35e8/regex-2026.7.19.tar.gz"
    sha256 "7e77b324909c1617cbb4c668677e2c6ae13f44d7c1de0d4f15f2e3c10f3315b5"
  end

  resource "pyobjc-core" do
    url "https://files.pythonhosted.org/packages/a5/78/abc4ce5920305780aeb36b4067a86253378b36e29ba96673a3deb02eb03a/pyobjc_core-12.2.2.tar.gz"
    sha256 "3906452339cd06a3bb07df103c2511d4cb0f7a22d8771c0b802eba15d9a642b6"
  end

  resource "pyobjc-framework-Cocoa" do
    url "https://files.pythonhosted.org/packages/75/76/49c6da2c6a831020b4854ba20079d5a1030474bffc776b7b73c2eeff8c15/pyobjc_framework_cocoa-12.2.2.tar.gz"
    sha256 "c96c0ef69a71afbbb0e6a7d594b455c5fe47d62e0db376ee7a2b4b828c16ace9"
  end

  resource "pyobjc-framework-Quartz" do
    url "https://files.pythonhosted.org/packages/35/b1/426a37c7ae37280b3ffca2571fb48f211946aee2f4ca31a603ed1943c4a7/pyobjc_framework_quartz-12.2.2.tar.gz"
    sha256 "810f97b210cfd93704d240860286dfd6df09f9f1c52525fc5c2166723aea3f9e"
  end

  def install
    virtualenv_install_with_resources
    # launchd will not create a missing directory for the log it is told to write,
    # and it fails quietly when it cannot -- `brew services start` reports success
    # and nothing runs.
    (var/"log").mkpath
  end

  service do
    run [opt_bin/"safepaste-daemon"]
    keep_alive true
    log_path var/"log/safepaste.log"
    error_log_path var/"log/safepaste.log"
  end

  def caveats
    <<~EOS
      SafePaste is installed but not yet running. Start it with:

        brew services start safepaste

      That places a shield in the menu bar and binds Ctrl+Alt+V to sanitise the
      clipboard on demand. Neither needs any permission.

      Automatic pasting is optional and off by default. Switching it on in
      ~/Library/Application Support/SafePaste/config.toml requires granting
      Accessibility permission in System Settings > Privacy & Security.

      The CLI works without the service:

        safepaste scan -      reads stdin, exits 1 if it finds a secret
        safepaste redact -    writes the sanitised text to stdout
        safepaste rules       lists the detectors

      Per-application policy is supported on macOS, keyed by bundle identifier.
      See the [policy] section in the README.
    EOS
  end

  test do
    # The detector is useless without its bundled rule data, and a broken install
    # would still exit zero on a trivial invocation -- so assert the rule count and
    # a real redaction rather than just that the binary runs.
    assert_match(/total rules: \d\d\d/, shell_output("#{bin}/safepaste rules --stats"))

    output = pipe_output(
      "#{bin}/safepaste redact -",
      "GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z\n",
    )
    assert_match "GITHUB_TOKEN=[REDACTED]", output

    # Clean text must pass through untouched and exit 0.
    assert_equal 0, shell_output("echo 'nothing here' | #{bin}/safepaste scan -; echo $?").to_i
  end
end
