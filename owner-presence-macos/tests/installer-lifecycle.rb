# Run only from a root-owned copy in the disposable macOS test lane.
require_relative "../install"
require "fileutils"

abort("root fixture required") unless Process.uid.zero? && Process.euid.zero?
Dir.mktmpdir("owner-installer-lifecycle-", "/private/tmp") do |scratch|
  target = File.join(scratch, "helpers")
  OwnerHelperInstall.send(:remove_const, :DIR)
  OwnerHelperInstall.const_set(:DIR, target)
  # Hosted runners have no release identity. Only signature verification is
  # stubbed here. File ownership, hashing, locking and publication are real.
  def OwnerHelperInstall.verify_release(_path, team, notarization: true)
    raise OwnerHelperInstall::ReleaseVerificationError unless team == "ABCDE12345"
  end
  team = "ABCDE12345"
  source = File.join(scratch, "payload")
  File.binwrite(source, "fixture executable")
  digest = Digest::SHA256.file(source).hexdigest
  binary = File.join(target, OwnerHelperInstall::ID)
  pin = binary + ".publisher"
  unrelated = File.join(target, "unrelated")
  install = -> { OwnerHelperInstall.install(source, team, digest) }
  remove = -> { OwnerHelperInstall.uninstall(team, digest) }

  raise unless remove.call.zero? && !File.exist?(target)
  Dir.mkdir(target, 0o700)
  File.binwrite(unrelated, "keep this file")
  install.call
  raise unless remove.call == 2 && remove.call.zero?
  raise if File.exist?(binary) || File.exist?(pin)
  [binary, pin].each do |missing|
    install.call
    File.unlink(missing)
    if missing == pin
      begin
        OwnerHelperInstall.uninstall("OTHER12345", digest)
        abort("different publisher accepted")
      rescue OwnerHelperInstall::ReleaseVerificationError
        raise unless File.file?(binary)
      end
    end
    raise unless remove.call == 1 && remove.call.zero?
  end

  install.call
  [binary, pin].each do |path|
    original = File.binread(path)
    File.binwrite(path, "replaced")
    begin
      remove.call
      abort("replacement accepted")
    rescue RuntimeError
      raise unless File.file?(binary) && File.file?(pin) && File.binread(path) == "replaced"
    end
    File.binwrite(path, original)
  end
  File.unlink(binary)
  File.symlink(unrelated, binary)
  begin
    remove.call
    abort("symlink accepted")
  rescue RuntimeError
    raise unless File.symlink?(binary) && File.file?(pin)
  end
  File.unlink(binary)
  remove.call

  children = [install, remove, install, remove].map { |operation| fork { operation.call } }
  children.each { |pid| raise unless Process.wait2(pid)[1].success? }
  raise unless File.exist?(binary) == File.exist?(pin)
  install.call
  raise unless File.binread(binary) == File.binread(source) && File.binread(pin) == "#{team}\n#{digest}\n"
  raise unless remove.call == 2 && Dir.children(target) == ["unrelated"] && File.binread(unrelated) == "keep this file"
end
puts "Owner helper install, removal, partial removal, conflicts, concurrency and reinstall passed."
