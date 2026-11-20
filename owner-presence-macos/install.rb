#!/usr/bin/ruby --disable-gems
# Run the reviewed installer from an administrator-controlled copy. Supply the
# signer team and sealed artifact SHA-256 independently from the release record.
require "digest"
require "fiddle/import"
require "open3"
require "tempfile"

module OwnerHelperInstall
  ID = "ai.true-line.agent-bot-owner-presence"
  DIR = "/Library/PrivilegedHelperTools"
  MAX_BYTES = 32 * 1024 * 1024

  def self.protected_path(path, mode = nil)
    s = File.lstat(path)
    raise unless s.uid.zero? && s.gid.zero? && (s.mode & 0o6022).zero?
    raise unless mode ? s.file? && s.nlink == 1 && (s.mode & 0o7777) == mode : s.directory?
    listing, ok = Open3.capture2e("/bin/ls", "-lde", path)
    raise unless ok.success? && listing.lines.one?
  end

  def self.matches(source, destination, mode)
    protected_path(destination, mode)
    raise unless File.size(destination) == File.size(source) &&
                 Digest::SHA256.file(destination) == Digest::SHA256.file(source)
  end

  module DarwinRename
    extend Fiddle::Importer
    dlload "/usr/lib/libSystem.B.dylib"
    extern "int renamex_np(const char *, const char *, unsigned int)"
  end

  def self.publish(source, destination, mode)
    # RENAME_EXCL creates one final name atomically. Even if the installer
    # exits here, the protected file has the single link required at use.
    return if DarwinRename.renamex_np(source, destination, 0x00000004).zero?
    code = Fiddle.last_error
    raise SystemCallError.new("publish", code) unless code == Errno::EEXIST::Errno
    matches(source, destination, mode)
  end

  class ReleaseVerificationError < StandardError; end

  def self.verify_release(binary, team, notarization: true)
    requirement = %(anchor apple generic and identifier "#{ID}" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[subject.OU] = "#{team}" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists)
    # A fresh Mac may have no local ticket for a notarized flat executable.
    # codesign can retrieve Apple's ticket during installation.
    options = ["--verify", "--strict", "--all-architectures"]
    if notarization
      options << "--check-notarization"
      requirement += " and notarized"
    end
    verified = system("/usr/bin/codesign", *options,
                      "-R=" + requirement, binary, out: File::NULL, err: File::NULL)
    raise ReleaseVerificationError unless verified
  end

  def self.check_administrator(team, digest)
    raise unless Process.uid.zero? && Process.euid.zero? &&
                 /\A[A-Z0-9]{10}\z/.match?(team) && /\A[0-9a-f]{64}\z/.match?(digest)
    ["/", "/Library"].each { |path| protected_path(path) }
  end

  def self.with_install_lock
    File.open(DIR, File::RDONLY | File::NOFOLLOW) do |parent|
      raise unless parent.flock(File::LOCK_EX)
      yield
    end
  end

  def self.install(source, team, digest)
    check_administrator(team, digest)
    protected_path(DIR)
    # Build both payloads in a root-only directory on the destination filesystem.
    # Publish without replacing. A retry can complete an identical partial install.
    Dir.mktmpdir(".owner-install-", DIR) do |stage|
      binary = File.join(stage, ID)
      pin = File.join(stage, ID + ".publisher")
      File.open(source, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |input|
        raise unless input.stat.file? && (1..MAX_BYTES).cover?(input.stat.size)
        File.open(binary, "wb", 0o600) { |out| IO.copy_stream(input, out, MAX_BYTES + 1) }
      end
      raise unless File.size(binary) <= MAX_BYTES && Digest::SHA256.file(binary).hexdigest == digest
      File.chown(0, 0, binary)
      File.chmod(0o555, binary)
      verify_release(binary, team)
      File.binwrite(pin, "#{team}\n#{digest}\n")
      File.chown(0, 0, pin)
      File.chmod(0o444, pin)
      files = [[pin, File.join(DIR, ID + ".publisher"), 0o444], [binary, File.join(DIR, ID), 0o555]]
      with_install_lock do
        files.each do |file, dest, mode|
          begin
            matches(file, dest, mode)
          rescue Errno::ENOENT
            # Missing destinations are expected on first installation.
          end
        end
        files.each { |file, dest, mode| publish(file, dest, mode) }
      end
    end
  end

  # Check all surviving parts before removing either. An interrupted removal
  # can leave one approved part, so either name may already be absent.
  def self.uninstall(team, digest)
    check_administrator(team, digest)
    begin
      protected_path(DIR)
    rescue Errno::ENOENT
      return 0
    end
    with_install_lock do
      binary = File.join(DIR, ID)
      pin = binary + ".publisher"
      remaining = []
      [[binary, 0o555], [pin, 0o444]].each do |path, mode|
        begin
          protected_path(path, mode)
        rescue Errno::ENOENT
          next
        end
        if path == binary
          raise unless (1..MAX_BYTES).cover?(File.size(path)) && Digest::SHA256.file(path).hexdigest == digest
        else
          expected = "#{team}\n#{digest}\n"
          raise unless File.size(path) == expected.bytesize && File.binread(path) == expected
        end
        remaining << path
      end
      # With the publisher record missing, verify the team on the surviving binary.
      verify_release(binary, team, notarization: false) if remaining == [binary]
      remaining.each { |path| File.unlink(path) }
      remaining.length
    end
  end
end

if $PROGRAM_NAME == __FILE__
  abort("usage: install.rb SIGNED_EXECUTABLE|--uninstall APPROVED_TEAM APPROVED_SHA256") unless ARGV.length == 3
  begin
    if ARGV.first == "--uninstall"
      count = OwnerHelperInstall.uninstall(*ARGV.drop(1))
      puts count.zero? ? "Owner CLI already absent." : "Removed owner CLI installation files."
    else
      OwnerHelperInstall.install(*ARGV)
    end
  rescue OwnerHelperInstall::ReleaseVerificationError
    abort("Owner helper removal refused. Check the installed signature and approved publisher.") if ARGV.first == "--uninstall"
    abort("Could not verify the approved Developer ID signature and Apple notarization. Check the release and connectivity to Apple.")
  rescue StandardError
    action = ARGV.first == "--uninstall" ? "removal" : "installation"
    abort("Owner helper #{action} refused. Check administrator ownership and the approved signed release.")
  end
end
