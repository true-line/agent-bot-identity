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

  def self.install(source, team, digest)
    raise unless Process.uid.zero? && Process.euid.zero? &&
                 /\A[A-Z0-9]{10}\z/.match?(team) && /\A[0-9a-f]{64}\z/.match?(digest)
    ["/", "/Library", DIR].each { |path| protected_path(path) }
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
      requirement = %(anchor apple generic and identifier "#{ID}" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[subject.OU] = "#{team}" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and notarized)
      raise unless system("/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "-R=" + requirement, binary,
                          out: File::NULL, err: File::NULL)
      File.binwrite(pin, "#{team}\n#{digest}\n")
      File.chown(0, 0, pin)
      File.chmod(0o444, pin)
      files = [[pin, File.join(DIR, ID + ".publisher"), 0o444], [binary, File.join(DIR, ID), 0o555]]
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

if $PROGRAM_NAME == __FILE__
  abort("usage: install.rb SIGNED_EXECUTABLE APPROVED_TEAM APPROVED_SHA256") unless ARGV.length == 3
  begin
    OwnerHelperInstall.install(*ARGV)
  rescue StandardError
    abort("Owner helper installation refused. Check administrator ownership and the approved signed release.")
  end
end
