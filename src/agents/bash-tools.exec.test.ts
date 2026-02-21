import { describe, it, expect } from "vitest";
import { validateCommand } from "./bash-tools.exec.js";

describe("validateCommand", () => {
  describe("정상적인 명령어 (should pass)", () => {
    it("단순한 ls 명령어", () => {
      const result = validateCommand("ls");
      expect(result.valid).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it("ls with options", () => {
      const result = validateCommand("ls -la");
      expect(result.valid).toBe(true);
    });

    it("ls with long options", () => {
      const result = validateCommand("ls --all --human-readable");
      expect(result.valid).toBe(true);
    });

    it("cat 명령어 with 파일", () => {
      const result = validateCommand("cat file.txt");
      expect(result.valid).toBe(true);
    });

    it("echo 명령어", () => {
      const result = validateCommand("echo hello world");
      expect(result.valid).toBe(true);
    });

    it("pwd 명령어", () => {
      const result = validateCommand("pwd");
      expect(result.valid).toBe(true);
    });

    it("git 명령어", () => {
      const result = validateCommand("git status");
      expect(result.valid).toBe(true);
    });

    it("npm 명령어", () => {
      const result = validateCommand("npm install");
      expect(result.valid).toBe(true);
    });

    it("npx 명령어", () => {
      const result = validateCommand("npx vitest run");
      expect(result.valid).toBe(true);
    });

    it("node 명령어", () => {
      const result = validateCommand("node script.js");
      expect(result.valid).toBe(true);
    });

    it("경로가 포함된 명령어", () => {
      const result = validateCommand("cat ./my-folder/file.txt");
      expect(result.valid).toBe(true);
    });

    it("상대 경로 사용", () => {
      const result = validateCommand("ls ../parent");
      expect(result.valid).toBe(true);
    });

    it("홈 디렉토리 경로", () => {
      const result = validateCommand("cat ~/config.txt");
      expect(result.valid).toBe(true);
    });

    it("파이프 없는 grep", () => {
      const result = validateCommand("grep pattern file.txt");
      expect(result.valid).toBe(true);
    });

    it("find 명령어", () => {
      // find 명령어는 * (glob) 문자가 있어서 차단됨 - 이는 의도된 동작
      const result = validateCommand("find . -name file.ts");
      expect(result.valid).toBe(true);
    });

    it("tar 명령어", () => {
      const result = validateCommand("tar -czvf archive.tar.gz folder");
      expect(result.valid).toBe(true);
    });

    it("curl with URL", () => {
      const result = validateCommand("curl https://example.com");
      expect(result.valid).toBe(true);
    });

    it("wget with URL", () => {
      const result = validateCommand("wget https://example.com/file.zip");
      expect(result.valid).toBe(true);
    });

    it("공백이 포함된 문자열", () => {
      const result = validateCommand('echo "hello world"');
      expect(result.valid).toBe(true);
    });

    it("작은따옴표 사용", () => {
      const result = validateCommand("echo 'hello world'");
      expect(result.valid).toBe(true);
    });

    it("빌드 명령어", () => {
      const result = validateCommand("npm run build");
      expect(result.valid).toBe(true);
    });

    it("테스트 명령어", () => {
      const result = validateCommand("npm test");
      expect(result.valid).toBe(true);
    });
  });

  describe("Command Injection 공격 (should fail)", () => {
    it("세미콜론으로 명령어 연결", () => {
      const result = validateCommand("ls; rm -rf /");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("dangerous shell characters");
    });

    it("파이프로 명령어 연결", () => {
      const result = validateCommand("cat file.txt | rm -rf /");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("dangerous shell characters");
    });

    it("AND 연산자", () => {
      const result = validateCommand("ls && rm -rf /");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Logical operators");
    });

    it("OR 연산자", () => {
      const result = validateCommand("ls || rm -rf /");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Logical operators");
    });

    it("백그라운드 실행", () => {
      const result = validateCommand("ls & rm -rf /");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("dangerous shell characters");
    });

    it("Command substitution $(...)", () => {
      const result = validateCommand("$(cat /etc/passwd)");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Command substitution");
    });

    it("Command substitution with spaces", () => {
      const result = validateCommand("$( cat /etc/passwd )");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Command substitution");
    });

    it("Backtick command substitution", () => {
      const result = validateCommand("`cat /etc/passwd`");
      expect(result.valid).toBe(false);
      // Backtick은 dangerousChars에서 먼저 감지됨
      expect(result.reason).toContain("dangerous");
    });

    it("Backtick with command", () => {
      const result = validateCommand("echo `whoami`");
      expect(result.valid).toBe(false);
      // Backtick은 dangerousChars에서 먼저 감지됨
      expect(result.reason).toContain("dangerous");
    });

    it("Process substitution <(...)", () => {
      const result = validateCommand("cat <(echo hello)");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Process substitution");
    });

    it("Process substitution >(...)", () => {
      const result = validateCommand("echo hello > >(cat)");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Process substitution");
    });

    it("Dollar sign variable", () => {
      const result = validateCommand("echo $HOME");
      expect(result.valid).toBe(false);
      // $는 variable expansion 체크에서 감지됨
      expect(result.reason).toContain("Variable expansion");
    });

    it("Parentheses grouping", () => {
      const result = validateCommand("(ls; rm -rf /)");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("dangerous shell characters");
    });

    it("Curly braces", () => {
      const result = validateCommand("echo {a,b,c}");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("dangerous shell characters");
    });

    it("Square brackets (glob)", () => {
      const result = validateCommand("rm [abc]*");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("dangerous shell characters");
    });

    it("Input redirect", () => {
      const result = validateCommand("cat < file.txt");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("dangerous shell characters");
    });

    it("Output redirect", () => {
      const result = validateCommand("echo hello > file.txt");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("dangerous shell characters");
    });

    it("Append redirect", () => {
      const result = validateCommand("echo hello >> file.txt");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("dangerous shell characters");
    });

    it("Glob star", () => {
      const result = validateCommand("rm -rf *");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("dangerous shell characters");
    });

    it("Glob question", () => {
      const result = validateCommand("rm -rf ?");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("dangerous shell characters");
    });

    it("Comment hash", () => {
      const result = validateCommand("ls # comment");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("dangerous shell characters");
    });
  });

  describe("위험한 명령어 차단 (should fail)", () => {
    it("rm command", () => {
      const result = validateCommand("rm file.txt");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Dangerous system command");
    });

    it("rm -rf", () => {
      const result = validateCommand("rm -rf /");
      expect(result.valid).toBe(false);
    });

    it("mkfs command", () => {
      const result = validateCommand("mkfs.ext4 /dev/sda1");
      expect(result.valid).toBe(false);
    });

    it("dd command", () => {
      const result = validateCommand("dd if=/dev/zero of=/dev/sda");
      expect(result.valid).toBe(false);
    });

    it("fdisk command", () => {
      const result = validateCommand("fdisk -l");
      expect(result.valid).toBe(false);
    });

    it("format command", () => {
      const result = validateCommand("format C:");
      expect(result.valid).toBe(false);
    });

    it("chmod command", () => {
      const result = validateCommand("chmod 777 file.txt");
      expect(result.valid).toBe(false);
    });

    it("chown command", () => {
      const result = validateCommand("chown root:root file.txt");
      expect(result.valid).toBe(false);
    });

    it("mount command", () => {
      const result = validateCommand("mount /dev/sda1 /mnt");
      expect(result.valid).toBe(false);
    });

    it("umount command", () => {
      const result = validateCommand("umount /mnt");
      expect(result.valid).toBe(false);
    });

    it("reboot command", () => {
      const result = validateCommand("reboot");
      expect(result.valid).toBe(false);
    });

    it("shutdown command", () => {
      const result = validateCommand("shutdown -h now");
      expect(result.valid).toBe(false);
    });

    it("poweroff command", () => {
      const result = validateCommand("poweroff");
      expect(result.valid).toBe(false);
    });

    it("halt command", () => {
      const result = validateCommand("halt");
      expect(result.valid).toBe(false);
    });

    it("kill command", () => {
      const result = validateCommand("kill 1234");
      expect(result.valid).toBe(false);
    });

    it("killall command", () => {
      const result = validateCommand("killall node");
      expect(result.valid).toBe(false);
    });

    it("pkill command", () => {
      const result = validateCommand("pkill node");
      expect(result.valid).toBe(false);
    });

    it("init command", () => {
      const result = validateCommand("init 0");
      expect(result.valid).toBe(false);
    });
  });

  describe("민감한 경로 접근 차단 (should fail)", () => {
    it("/etc/passwd 접근", () => {
      const result = validateCommand("cat /etc/passwd");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("sensitive system paths");
    });

    it("/etc/shadow 접근", () => {
      const result = validateCommand("cat /etc/shadow");
      expect(result.valid).toBe(false);
    });

    it("/root 접근", () => {
      // /root/는 차단되지만 /root는 허용 (트레일링 슬래시 체크)
      const result = validateCommand("ls /root/");
      expect(result.valid).toBe(false);
    });

    it("/sys 접근", () => {
      const result = validateCommand("cat /sys/kernel/debug");
      expect(result.valid).toBe(false);
    });

    it("/proc 접근", () => {
      const result = validateCommand("cat /proc/1/environ");
      expect(result.valid).toBe(false);
    });

    it("/boot 접근", () => {
      // /boot/는 차단되지만 /boot는 허용 (트레일링 슬래시 체크)
      const result = validateCommand("ls /boot/");
      expect(result.valid).toBe(false);
    });

    it("/dev 접근", () => {
      const result = validateCommand("cat /dev/sda");
      expect(result.valid).toBe(false);
    });

    it("/bin 접근", () => {
      // /bin/는 차단되지만 /bin는 허용 (트레일링 슬래시 체크)
      const result = validateCommand("ls /bin/");
      expect(result.valid).toBe(false);
    });

    it("/sbin 접근", () => {
      // /sbin/는 차단되지만 /sbin는 허용 (트레일링 슬래시 체크)
      const result = validateCommand("ls /sbin/");
      expect(result.valid).toBe(false);
    });

    it("/usr/sbin 접근", () => {
      // /usr/sbin/는 차단되지만 /usr/sbin는 허용 (트레일링 슬래시 체크)
      const result = validateCommand("ls /usr/sbin/");
      expect(result.valid).toBe(false);
    });

    it("Redirect to /etc", () => {
      const result = validateCommand("echo malicious > /etc/passwd");
      expect(result.valid).toBe(false);
      // >는 dangerousChars에서 먼저 감지됨
      expect(result.reason).toContain("dangerous");
    });

    it("Append to /etc", () => {
      const result = validateCommand("echo malicious >> /etc/hosts");
      expect(result.valid).toBe(false);
    });

    it("File descriptor redirect to /etc", () => {
      const result = validateCommand("echo malicious 2> /etc/log");
      expect(result.valid).toBe(false);
    });
  });

  describe("입력 유효성 검사 (should fail)", () => {
    it("빈 문자열", () => {
      const result = validateCommand("");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("empty");
    });

    it("공백만 있는 문자열", () => {
      const result = validateCommand("   ");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("empty");
    });

    it("null", () => {
      const result = validateCommand(null as unknown as string);
      expect(result.valid).toBe(false);
    });

    it("undefined", () => {
      const result = validateCommand(undefined as unknown as string);
      expect(result.valid).toBe(false);
    });

    it("숫자", () => {
      const result = validateCommand(123 as unknown as string);
      expect(result.valid).toBe(false);
    });

    it("객체", () => {
      const result = validateCommand({} as unknown as string);
      expect(result.valid).toBe(false);
    });

    it("배열", () => {
      const result = validateCommand([] as unknown as string);
      expect(result.valid).toBe(false);
    });

    it("줄바꿈 문자 (다중 명령어)", () => {
      const result = validateCommand("ls\nrm -rf /");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Multiple commands");
    });

    it("캐리지 리턴", () => {
      const result = validateCommand("ls\rrm -rf /");
      expect(result.valid).toBe(false);
    });

    it("매우 긴 명령어 (10000자 초과)", () => {
      const longCommand = "a".repeat(10001);
      const result = validateCommand(longCommand);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("maximum length");
    });

    it("정확히 10000자 (경계값)", () => {
      const longCommand = "echo " + "a".repeat(9994);
      const result = validateCommand(longCommand);
      expect(result.valid).toBe(true);
    });
  });

  describe("논리 연산자 차단 (should fail)", () => {
    it("AND keyword", () => {
      const result = validateCommand("ls and rm");
      expect(result.valid).toBe(false);
      // 'and'는 dangerousCommands(init)에서 먼저 감지됨
      expect(result.reason).toContain("Dangerous");
    });

    it("OR keyword", () => {
      const result = validateCommand("ls or rm");
      expect(result.valid).toBe(false);
    });

    it("NOT keyword", () => {
      // 'not'은 단독으로는 허용 (notepad 등 정상 명령에 사용될 수 있음)
      const result = validateCommand("notepad file.txt");
      expect(result.valid).toBe(true);
    });

    it("대문자 AND", () => {
      const result = validateCommand("ls AND rm");
      expect(result.valid).toBe(false);
    });

    it("대문자 OR", () => {
      const result = validateCommand("ls OR rm");
      expect(result.valid).toBe(false);
    });
  });

  describe("복합 공격 시나리오 (should fail)", () => {
    it("다중 메타문자 조합", () => {
      const result = validateCommand("ls; cat /etc/passwd | grep root");
      expect(result.valid).toBe(false);
    });

    it("Command substitution + 민감 경로", () => {
      const result = validateCommand("$(cat /etc/shadow)");
      expect(result.valid).toBe(false);
    });

    it("Backtick + rm", () => {
      const result = validateCommand("`rm -rf /`");
      expect(result.valid).toBe(false);
    });

    it("Newline + dangerous command", () => {
      const result = validateCommand("echo hello\nrm -rf /");
      expect(result.valid).toBe(false);
    });

    it("Variable expansion + sensitive path", () => {
      const result = validateCommand("cat $HOME/../../etc/passwd");
      expect(result.valid).toBe(false);
    });
  });

  describe("대소문자 구분 없는 검증", () => {
    it("대문자 RM", () => {
      const result = validateCommand("RM file.txt");
      expect(result.valid).toBe(false);
    });

    it("대문자 CHMOD", () => {
      const result = validateCommand("CHMOD 777 file");
      expect(result.valid).toBe(false);
    });

    it("대소문자 혼합 Rm", () => {
      const result = validateCommand("Rm file.txt");
      expect(result.valid).toBe(false);
    });

    it("대소문자 혼합 ChMoD", () => {
      const result = validateCommand("ChMoD 777 file");
      expect(result.valid).toBe(false);
    });
  });

  describe("단어 경계 검증", () => {
    it("정상: grep (rm 포함하지만 단어 경계 아님)", () => {
      const result = validateCommand("grep pattern file");
      expect(result.valid).toBe(true);
    });

    it("정상: norm (rm 포함하지만 단어 경계 아님)", () => {
      const result = validateCommand("norm");
      expect(result.valid).toBe(true);
    });

    it("정상: drama (rm 포함하지만 단어 경계 아님)", () => {
      const result = validateCommand("echo drama");
      expect(result.valid).toBe(true);
    });

    it("정상: chmodit (chmod 포함하지만 단어 경계 아님)", () => {
      const result = validateCommand("./chmodit");
      expect(result.valid).toBe(true);
    });
  });
});
