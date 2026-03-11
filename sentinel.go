package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	RST     = "\033[0m"
	BLD     = "\033[1m"
	DIM     = "\033[2m"
	RED     = "\033[91m"
	RDB     = "\033[91;1m"
	YEL     = "\033[93m"
	GRN     = "\033[92m"
	CYN     = "\033[96m"
	MAG     = "\033[95m"
	BLU     = "\033[94m"
	GRY     = "\033[90m"
	WHT     = "\033[97m"
	LVL_INFO = 0
	LVL_LOW  = 1
	LVL_MED  = 2
	LVL_HIGH = 3
	LVL_CRIT = 4
	maxFileScan = 8 << 20
	blitzRead   = 32768
	VERSION     = "8.0"
)

var (
	lvlName  = [5]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	lvlIcon  = [5]string{"ℹ️ ", "🔷", "🔶", "⚠️ ", "🚨"}
	lvlColor = [5]string{CYN, CYN, YEL, RED, RDB}
	selfPath string
	printMu  sync.Mutex
)

// ═══════════════════ UTILS ═══════════════════

func env(k string) string { return os.Getenv(k) }
func envOr(k, fb string) string {
	if v := env(k); v != "" { return v }; return fb
}
func trunc(s string, n int) string {
	if len(s) <= n { return s }; return s[:n] + "..."
}
func sanitize(s string) string {
	return strings.NewReplacer("'", "`", "\"", "`", "\n", " ", "\r", "").Replace(s)
}
func exists(p string) bool { _, e := os.Stat(p); return e == nil }
func enableAnsi() {
	k := syscall.NewLazyDLL("kernel32.dll")
	h, _, _ := k.NewProc("GetStdHandle").Call(uintptr(^uintptr(10)))
	k.NewProc("SetConsoleMode").Call(h, 7)
}
func md5sum(path string) string {
	f, e := os.Open(path); if e != nil { return "" }
	defer f.Close(); h := md5.New(); io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}
func sha256sum(path string) string {
	f, e := os.Open(path); if e != nil { return "" }
	defer f.Close(); h := sha256.New(); io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}
func sha256bytes(data []byte) string {
	h := sha256.Sum256(data); return hex.EncodeToString(h[:])
}
func entropy(data []byte) float64 {
	if len(data) == 0 { return 0 }
	var freq [256]float64
	for _, b := range data { freq[b]++ }
	n := float64(len(data)); var e float64
	for _, f := range freq {
		if f > 0 { p := f / n; e -= p * math.Log2(p) }
	}
	return e
}
func runCmd(name string, args ...string) string {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, _ := c.Output(); return string(out)
}
func runCmdTimeout(timeout time.Duration, name string, args ...string) string {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	timer := time.AfterFunc(timeout, func() {
		if c.Process != nil { c.Process.Kill() }
	})
	out, _ := c.Output(); timer.Stop(); return string(out)
}
func pidMap() map[string]string {
	m := make(map[string]string)
	out := runCmd("tasklist", "/fo", "csv", "/nh")
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ",", 3)
		if len(parts) >= 2 {
			m[strings.Trim(parts[1], `"`)] = strings.Trim(parts[0], `"`)
		}
	}
	return m
}
func countFiles(dir string) int {
	count := 0
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() { count++ }; return nil
	})
	return count
}

// ═══════════════════ CACHE ═══════════════════

type CacheEntry struct {
	Size int64 `json:"s"`; Mtime int64 `json:"m"`; Safe bool `json:"ok"`; Scanned int64 `json:"t"`
}
type ScanCache struct {
	mu sync.Mutex; entries map[string]CacheEntry; path string; dirty bool
}

func NewCache(p string) *ScanCache {
	c := &ScanCache{entries: make(map[string]CacheEntry), path: p}
	if d, e := os.ReadFile(p); e == nil { json.Unmarshal(d, &c.entries) }
	return c
}
func (c *ScanCache) Save() {
	c.mu.Lock(); defer c.mu.Unlock()
	if !c.dirty { return }
	d, _ := json.Marshal(c.entries); os.WriteFile(c.path, d, 0o644); c.dirty = false
}
func (c *ScanCache) IsNew(p string, sz, mt int64) bool {
	c.mu.Lock(); defer c.mu.Unlock()
	if e, ok := c.entries[p]; ok { return e.Size != sz || e.Mtime != mt }; return true
}
func (c *ScanCache) Set(p string, sz, mt int64) {
	c.mu.Lock(); defer c.mu.Unlock()
	c.entries[p] = CacheEntry{sz, mt, true, time.Now().Unix()}; c.dirty = true
}
func (c *ScanCache) Count() int  { c.mu.Lock(); defer c.mu.Unlock(); return len(c.entries) }
func (c *ScanCache) Clear()      { c.mu.Lock(); defer c.mu.Unlock(); c.entries = make(map[string]CacheEntry); c.dirty = true }

// ═══════════════════ ALERTES ═══════════════════

type Alert struct {
	Time    time.Time `json:"time"`
	Level   int       `json:"level"`
	Module  string    `json:"module"`
	Message string    `json:"message"`
	Path    string    `json:"path,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}
type TimelineEvent struct {
	Time   time.Time `json:"time"`
	Type   string    `json:"type"`
	Detail string    `json:"detail"`
}
type AlertSystem struct {
	mu        sync.Mutex
	items     []Alert
	cd        map[string]time.Time
	lastNotif time.Time
	logFile   *os.File
	timeline  []TimelineEvent
}

func NewAlerts(logPath string) *AlertSystem {
	os.MkdirAll(filepath.Dir(logPath), 0o755)
	f, _ := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	return &AlertSystem{cd: make(map[string]time.Time), logFile: f}
}
func (a *AlertSystem) Fire(lvl int, mod, msg, path, det string) {
	a.mu.Lock(); defer a.mu.Unlock()
	key := mod + "|" + msg + "|" + path
	if t, ok := a.cd[key]; ok && time.Since(t) < 10*time.Minute { return }
	a.cd[key] = time.Now()
	it := Alert{time.Now(), lvl, mod, msg, path, det}
	a.items = append(a.items, it)
	if len(a.items) > 1000 { a.items = a.items[len(a.items)-1000:] }
	a.timeline = append(a.timeline, TimelineEvent{time.Now(), lvlName[lvl], fmt.Sprintf("[%s] %s", mod, msg)})
	if len(a.timeline) > 2000 { a.timeline = a.timeline[len(a.timeline)-2000:] }
	ts := it.Time.Format("15:04:05")
	printMu.Lock()
	fmt.Printf("\n  %s %s[%s][%s]%s %s%s%s: %s\n", lvlIcon[lvl], lvlColor[lvl], ts, lvlName[lvl], RST, BLD, mod, RST, msg)
	if path != "" { fmt.Printf("       %s📁 %s%s\n", DIM, path, RST) }
	if det != "" { fmt.Printf("       %s%s%s\n", DIM, trunc(det, 150), RST) }
	fmt.Printf("  %ssentinel>%s ", CYN, RST)
	printMu.Unlock()
	if a.logFile != nil {
		fmt.Fprintf(a.logFile, "[%s][%s] %s: %s | %s | %s\n", ts, lvlName[lvl], mod, msg, path, det)
	}
	if lvl >= LVL_CRIT && time.Since(a.lastNotif) > 5*time.Minute {
		a.lastNotif = time.Now(); go winNotify("SENTINEL 🛡️ "+mod, sanitize(msg))
	}
}
func (a *AlertSystem) FireSilent(lvl int, mod, msg, path, det string) {
	a.mu.Lock(); defer a.mu.Unlock()
	a.items = append(a.items, Alert{time.Now(), lvl, mod, msg, path, det})
	a.timeline = append(a.timeline, TimelineEvent{time.Now(), lvlName[lvl], fmt.Sprintf("[%s] %s", mod, msg)})
}
func (a *AlertSystem) Show(count int) {
	a.mu.Lock(); defer a.mu.Unlock()
	s := len(a.items) - count; if s < 0 { s = 0 }
	if len(a.items) == 0 { fmt.Printf("\n  %s✅ Aucune alerte%s\n", GRN, RST); return }
	fmt.Printf("\n  %s📋 %d dernières alertes:%s\n", BLD, len(a.items)-s, RST)
	for _, x := range a.items[s:] {
		fmt.Printf("    %s [%s] %s: %s", lvlIcon[x.Level], x.Time.Format("15:04:05"), x.Module, x.Message)
		if x.Path != "" { fmt.Printf(" → %s", filepath.Base(x.Path)) }
		fmt.Println()
	}
}
func (a *AlertSystem) Total() int   { a.mu.Lock(); defer a.mu.Unlock(); return len(a.items) }
func (a *AlertSystem) All() []Alert {
	a.mu.Lock(); defer a.mu.Unlock()
	cp := make([]Alert, len(a.items)); copy(cp, a.items); return cp
}
func (a *AlertSystem) Timeline() []TimelineEvent {
	a.mu.Lock(); defer a.mu.Unlock()
	cp := make([]TimelineEvent, len(a.timeline)); copy(cp, a.timeline); return cp
}

func winNotify(title, msg string) {
	ps := fmt.Sprintf(`Add-Type -AN System.Windows.Forms;$n=New-Object Windows.Forms.NotifyIcon;`+
		`$n.Icon=[Drawing.SystemIcons]::Shield;$n.Visible=1;`+
		`$n.ShowBalloonTip(3000,'%s','%s','Warning');sleep 4;$n.Dispose()`,
		sanitize(title), sanitize(trunc(msg, 200)))
	c := exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	c.Start()
}

// ═══════════════════ MOTEUR DE SCAN ═══════════════════

type Pattern struct { Cat string; Lvl int; Rx *regexp.Regexp }
type Engine struct {
	scriptPats []Pattern; binPats []Pattern; malNames []string
	iocHashes  map[string]string; mu sync.RWMutex
}

func NewEngine() *Engine {
	e := &Engine{iocHashes: make(map[string]string)}

	sp := []struct{ c string; l int; r string }{
		{"Webhook Discord", LVL_CRIT, `https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+`},
		{"Telegram Bot", LVL_CRIT, `api\.telegram\.org/bot[\w:]+/send`},
		{"Token Discord", LVL_CRIT, `['"\x60][A-Za-z\d]{24,28}\.[A-Za-z\d_\-]{6}\.[A-Za-z\d_\-]{27,}['"\x60]`},
		{"Token MFA", LVL_CRIT, `mfa\.[A-Za-z\d_\-]{84}`},
		{"CryptUnprotect", LVL_HIGH, `(?i)CryptUnprotectData`},
		{"win32crypt", LVL_HIGH, `(?i)win32crypt\.CryptUnprotectData`},
		{"Browser DB Theft", LVL_HIGH, `(?i)(?:Login\s*Data|Local\s*State).*(?:shutil\.copy|copyfile)`},
		{"Discord LevelDB", LVL_HIGH, `(?i)discord(?:canary|ptb)?[/\\\\]+(?:Local.Storage|leveldb).*(?:open|glob)`},
		{"Keylogger Code", LVL_HIGH, `(?i)(?:pynput\.keyboard|SetWindowsHookEx\s*\(.*WH_KEYBOARD)`},
		{"Exec obfusqué", LVL_HIGH, `(?i)exec\s*\(\s*(?:base64\.b64decode|codecs\.decode|marshal\.loads)`},
		{"Registry Persist", LVL_HIGH, `(?i)(?:winreg|RegSetValueEx).*CurrentVersion[/\\\\]Run`},
		{"HTTP Exfil", LVL_HIGH, `(?i)requests\.post\s*\(\s*['"\x60].*(?:webhook|discord\.com/api)`},
		{"AMSI Bypass", LVL_CRIT, `(?i)(?:amsiInitFailed|AmsiScanBuffer|amsi\.dll.*patch|SetProtectionLevel)`},
		{"PS Download Cradle", LVL_CRIT, `(?i)(?:IEX|Invoke-Expression)\s*\(\s*(?:New-Object\s+Net\.WebClient|Invoke-WebRequest|iwr|curl)`},
		{"Mimikatz", LVL_CRIT, `(?i)(?:sekurlsa::logonpasswords|lsadump::sam|privilege::debug)`},
		{"Shellcode Loader", LVL_CRIT, `(?i)(?:VirtualAlloc|VirtualProtect).*(?:PAGE_EXECUTE|0x40).*(?:RtlMoveMemory|Copy|Marshal)`},
		{"Process Injection", LVL_CRIT, `(?i)(?:OpenProcess|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx)`},
		{"WMI Persistence", LVL_HIGH, `(?i)(?:__EventFilter|CommandLineEventConsumer|__FilterToConsumerBinding)`},
		{"Credential Harvest", LVL_CRIT, `(?i)(?:findstr.*password|reg\s+query.*password|cmdkey\s+/list)`},
		{"AV Disable", LVL_CRIT, `(?i)(?:Set-MpPreference\s+-Disable|sc\s+stop\s+WinDefend|netsh\s+advfirewall\s+set.*off)`},
		{"Base64 Payload", LVL_HIGH, `(?i)(?:FromBase64String|atob|b64decode)\s*\(\s*['"\x60][A-Za-z0-9+/=]{100,}`},
		{"Reverse Shell", LVL_CRIT, `(?i)(?:TCPClient|Net\.Sockets|bash\s+-i\s+>&|/dev/tcp/|nc\s+-e|ncat\s+--exec)`},
		{"UAC Bypass", LVL_CRIT, `(?i)(?:fodhelper|eventvwr|computerdefaults|sdclt).*(?:ms-settings|shell\\\\open)`},
		{"Shadow Copy Delete", LVL_CRIT, `(?i)(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.*recoveryenabled.*no)`},
		{"Ransomware Indicator", LVL_CRIT, `(?i)(?:\.encrypted|\.locked|\.crypto|DECRYPT_INSTRUCTIONS|YOUR_FILES_ARE)`},
		{"COM Hijack", LVL_HIGH, `(?i)(?:InprocServer32|LocalServer32).*(?:scrobj\.dll|rundll32)`},
		{"DNS Exfil", LVL_HIGH, `(?i)(?:nslookup|Resolve-DnsName).*(?:txt|TXT).*\$`},
		{"Clipboard Steal", LVL_HIGH, `(?i)(?:Get-Clipboard|win32clipboard|pyperclip|ctypes.*CF_TEXT)`},
		{"Screen Capture", LVL_MED, `(?i)(?:screenshot|PrintWindow|BitBlt.*GetDC|ImageGrab\.grab|pyautogui\.screenshot)`},
		{"Webcam Access", LVL_HIGH, `(?i)(?:VideoCapture|cv2\.VideoCapture|DirectShow.*Capture|escapi)`},
		{"SSH Key Steal", LVL_CRIT, `(?i)(?:\.ssh[/\\\\](?:id_rsa|id_ed25519|known_hosts)|ssh-keygen.*-f)`},
		{"Crypto Wallet", LVL_CRIT, `(?i)(?:wallet\.dat|exodus|metamask|phantom|electrum).*(?:copy|read|steal|grab)`},
		{"Browser Cookie Steal", LVL_CRIT, `(?i)(?:Cookies|cookies\.sqlite).*(?:copy|shutil|steal|decrypt)`},
		{"Persistence via DLL", LVL_HIGH, `(?i)(?:AppInit_DLLs|AppCertDlls|Winlogon\\\\Notify)`},
		{"Named Pipe C2", LVL_HIGH, `(?i)(?:CreateNamedPipe|ConnectNamedPipe).*(?:\\\\\.\\\\pipe)`},
	}
	for _, d := range sp {
		if rx, err := regexp.Compile(d.r); err == nil {
			e.scriptPats = append(e.scriptPats, Pattern{d.c, d.l, rx})
		}
	}

	bp := []struct{ c string; l int; r string }{
		{"Webhook Discord", LVL_CRIT, `https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]{60,}`},
		{"Telegram Bot", LVL_CRIT, `api\.telegram\.org/bot[\w:]+/send`},
		{"Suspicious URL", LVL_HIGH, `https?://(?:pastebin\.com|hastebin\.com|rentry\.co|transfer\.sh)/\w+`},
		{"C2 Beacon", LVL_CRIT, `(?i)(?:beacon|cobalt|metasploit|meterpreter|sliver)`},
		{"Crypto Miner", LVL_HIGH, `(?i)(?:stratum\+tcp://|xmrig|monero|cryptonight|hashrate)`},
	}
	for _, d := range bp {
		if rx, err := regexp.Compile(d.r); err == nil {
			e.binPats = append(e.binPats, Pattern{d.c, d.l, rx})
		}
	}

	e.malNames = []string{
		"luna-grabber", "luna_grabber", "lunagrabber", "empyrean-stealer",
		"blank-grabber", "blankgrabber", "hazard-grabber", "mercurial-grabber",
		"pysteal.py", "pystealer.py", "cstealer", "doenerium",
		"skuld-stealer", "umbral-stealer", "44caliber", "redline-stealer",
		"raccoon-stealer", "vidar-stealer", "mars-stealer", "aurora-stealer",
		"stealc", "risepro", "lumma-stealer", "mystic-stealer",
		"atomic-stealer", "poseidon-stealer", "bandit-stealer",
	}
	e.loadIOC()
	return e
}

func (e *Engine) loadIOC() {
	iocPath := filepath.Join(env("USERPROFILE"), ".sentinel", "ioc_hashes.json")
	if data, err := os.ReadFile(iocPath); err == nil {
		json.Unmarshal(data, &e.iocHashes)
	}
}
func (e *Engine) CheckIOC(hash string) (string, bool) {
	e.mu.RLock(); defer e.mu.RUnlock()
	name, ok := e.iocHashes[hash]; return name, ok
}

var scriptExts = map[string]bool{
	".py": true, ".pyw": true, ".js": true, ".bat": true, ".cmd": true,
	".ps1": true, ".vbs": true, ".hta": true, ".wsf": true, ".jsx": true,
	".ts": true, ".mjs": true, ".cjs": true, ".reg": true,
}
var binExts = map[string]bool{
	".exe": true, ".scr": true, ".dll": true, ".com": true, ".msi": true,
	".sys": true, ".drv": true, ".ocx": true, ".cpl": true,
}

func (e *Engine) ShouldScan(p string) bool {
	ext := strings.ToLower(filepath.Ext(p)); return scriptExts[ext] || binExts[ext]
}
func (e *Engine) IsBin(p string) bool { return binExts[strings.ToLower(filepath.Ext(p))] }

type Hit struct { Cat, Sample string; Lvl int }

func (e *Engine) Scan(data []byte, bin bool) []Hit {
	pats := e.scriptPats; if bin { pats = e.binPats }
	var hits []Hit; seen := map[string]bool{}
	for _, p := range pats {
		if seen[p.Cat] { continue }
		if m := p.Rx.Find(data); m != nil {
			hits = append(hits, Hit{p.Cat, trunc(string(m), 100), p.Lvl}); seen[p.Cat] = true
		}
	}
	return hits
}
func (e *Engine) CheckName(p string) string {
	low := strings.ToLower(filepath.Base(p))
	for _, n := range e.malNames { if strings.Contains(low, n) { return n } }
	return ""
}

// ═══════════════════ YARALITE — PE ANALYSIS ═══════════════════

type PEInfo struct {
	IsPE           bool
	Is64           bool
	Sections       []PESection
	Imports        []string
	IsPacked       bool
	PackerName     string
	HasOverlay     bool
	Anomalies      []string
}
type PESection struct {
	Name     string; VirtSize, RawSize uint32; Entropy float64; Executable bool
}

func analyzePE(data []byte) PEInfo {
	info := PEInfo{}
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' { return info }
	info.IsPE = true

	peOffset := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOffset+24 > len(data) || data[peOffset] != 'P' || data[peOffset+1] != 'E' { return info }

	machine := binary.LittleEndian.Uint16(data[peOffset+4 : peOffset+6])
	info.Is64 = machine == 0x8664

	numSections := int(binary.LittleEndian.Uint16(data[peOffset+6 : peOffset+8]))

	// TimeDateStamp
	if peOffset+12 <= len(data) {
		ts := binary.LittleEndian.Uint32(data[peOffset+8 : peOffset+12])
		t := time.Unix(int64(ts), 0)
		if t.Year() < 2000 || t.Year() > time.Now().Year()+1 {
			info.Anomalies = append(info.Anomalies, fmt.Sprintf("Timestamp PE suspect: %s", t.Format("2006-01-02")))
		}
	}

	optHeaderSize := int(binary.LittleEndian.Uint16(data[peOffset+20 : peOffset+22]))
	sectionOffset := peOffset + 24 + optHeaderSize

	packers := map[string]string{
		"UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
		".ndata": "NSIS", "ASPack": "ASPack", ".adata": "ASPack",
		"Themida": "Themida", "VMProt": "VMProtect",
		".vmp0": "VMProtect", ".vmp1": "VMProtect", ".enigma": "Enigma",
	}

	for i := 0; i < numSections && sectionOffset+40 <= len(data); i++ {
		name := strings.TrimRight(string(data[sectionOffset:sectionOffset+8]), "\x00")
		virtSize := binary.LittleEndian.Uint32(data[sectionOffset+8 : sectionOffset+12])
		rawSize := binary.LittleEndian.Uint32(data[sectionOffset+16 : sectionOffset+20])
		rawOffset := binary.LittleEndian.Uint32(data[sectionOffset+20 : sectionOffset+24])
		chars := binary.LittleEndian.Uint32(data[sectionOffset+36 : sectionOffset+40])
		exec := chars&0x20000000 != 0
		writable := chars&0x80000000 != 0

		secEnd := int(rawOffset) + int(rawSize)
		if secEnd > len(data) { secEnd = len(data) }
		secEntropy := 0.0
		if int(rawOffset) < len(data) && rawSize > 0 {
			secEntropy = entropy(data[rawOffset:secEnd])
		}

		info.Sections = append(info.Sections, PESection{name, virtSize, rawSize, secEntropy, exec})

		if exec && writable {
			info.Anomalies = append(info.Anomalies, fmt.Sprintf("Section %s: RWX (W+X)", name))
		}
		if secEntropy > 7.2 && rawSize > 1024 {
			info.Anomalies = append(info.Anomalies, fmt.Sprintf("Section %s: haute entropie %.1f", name, secEntropy))
		}

		if packer, ok := packers[name]; ok && packer != "" {
			info.IsPacked = true; info.PackerName = packer
		}
		sectionOffset += 40
	}

	// Suspect imports
	suspImports := []string{
		"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
		"NtCreateThreadEx", "SetWindowsHookEx", "GetAsyncKeyState",
		"InternetOpenUrl", "URLDownloadToFile", "CryptUnprotectData",
		"AdjustTokenPrivileges", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
	}
	for _, imp := range suspImports {
		if strings.Contains(string(data), imp) { info.Imports = append(info.Imports, imp) }
	}
	return info
}

// ═══════════════════ DEV PROJECT DETECTION ═══════════════════

var devIndicators = []string{
	"bot-discord", "discord-bot", "discord_bot", "my-bot", "mybot", "selfbot",
}
var devCodePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:client|bot)\.(?:run|login|start)\s*\(`),
	regexp.MustCompile(`(?i)(?:discord\.Client|commands\.Bot|discord\.js)`),
	regexp.MustCompile(`(?i)(?:@bot\.command|@client\.event|on_ready)`),
	regexp.MustCompile(`(?i)TOKEN\s*=\s*(?:os\.(?:getenv|environ)|dotenv)`),
}

func isDevProject(path string, content []byte) bool {
	low := strings.ToLower(path)
	for _, ind := range devIndicators { if strings.Contains(low, ind) { return true } }
	for _, rx := range devCodePatterns { if rx.Match(content) { return true } }
	return false
}

// ═══════════════════ SKIP LISTS ═══════════════════

var skipDirNames = map[string]bool{
	"node_modules": true, ".git": true, "__pycache__": true, "venv": true, ".venv": true,
	"site-packages": true, "cache": true, "cache2": true, "code cache": true,
	"gpu cache": true, "shader cache": true, "crashpad": true, ".cargo": true,
	".rustup": true, "locales": true, "dictionaries": true, "swiftshader": true,
}
var skipPathSegments = []string{
	`\Code\User\History\`, `\Code\User\workspaceStorage\`, `\Chrome\User Data\`,
	`\Edge\User Data\`, `\Brave-Browser\User Data\`, `\Opera Software\`,
	`\Steam\htmlcache\`, `\Programs\Microsoft VS Code\`, `\Roblox\Versions\`,
	`\Spotify\Apps\`, `\ms-playwright`, `\Python\Python3`,
}

func shouldSkipPath(path string) bool {
	if strings.ToLower(path) == selfPath { return true }
	for _, s := range skipPathSegments { if strings.Contains(path, s) { return true } }
	return false
}

// ═══════════════════ QUARANTINE ═══════════════════

type QuarantineItem struct {
	Original string `json:"original"`; Quarpath string `json:"quarpath"`
	Hash string `json:"hash"`; Reason string `json:"reason"`
	Time time.Time `json:"time"`; Size int64 `json:"size"`
}
type Quarantine struct { dir string; mu sync.Mutex; items []QuarantineItem }

func NewQuarantine(dir string) *Quarantine {
	q := &Quarantine{dir: dir}; os.MkdirAll(dir, 0o755)
	if data, err := os.ReadFile(filepath.Join(dir, "quarantine.json")); err == nil {
		json.Unmarshal(data, &q.items)
	}
	return q
}
func (q *Quarantine) Add(path, reason string) error {
	q.mu.Lock(); defer q.mu.Unlock()
	info, err := os.Stat(path); if err != nil { return err }
	hash := sha256sum(path)
	quarName := fmt.Sprintf("%s_%s.quar", time.Now().Format("20060102_150405"), filepath.Base(path))
	quarPath := filepath.Join(q.dir, quarName)
	src, err := os.ReadFile(path); if err != nil { return err }
	if err := os.WriteFile(quarPath, src, 0o444); err != nil { return err }
	os.Remove(path)
	q.items = append(q.items, QuarantineItem{path, quarPath, hash, reason, time.Now(), info.Size()})
	q.save(); return nil
}
func (q *Quarantine) List() []QuarantineItem { q.mu.Lock(); defer q.mu.Unlock(); return q.items }
func (q *Quarantine) Restore(idx int) error {
	q.mu.Lock(); defer q.mu.Unlock()
	if idx < 0 || idx >= len(q.items) { return fmt.Errorf("index invalide") }
	item := q.items[idx]
	data, err := os.ReadFile(item.Quarpath); if err != nil { return err }
	if err := os.WriteFile(item.Original, data, 0o644); err != nil { return err }
	os.Remove(item.Quarpath)
	q.items = append(q.items[:idx], q.items[idx+1:]...)
	q.save(); return nil
}
func (q *Quarantine) save() {
	data, _ := json.MarshalIndent(q.items, "", "  ")
	os.WriteFile(filepath.Join(q.dir, "quarantine.json"), data, 0o644)
}

// ═══════════════════ HONEYPOT ═══════════════════

type Honeypot struct { a *AlertSystem; files map[string]time.Time; mu sync.Mutex }

func NewHoneypot(a *AlertSystem) *Honeypot {
	h := &Honeypot{a: a, files: make(map[string]time.Time)}
	hfList := []struct{ dir, name, content string }{
		{env("USERPROFILE"), "passwords.txt", "# Vault\nbank: admin123\n"},
		{env("USERPROFILE"), "crypto_wallet_backup.txt", "BTC Seed: abandon abandon abandon\n"},
		{filepath.Join(env("USERPROFILE"), "Documents"), "private_keys.txt", "-----BEGIN RSA PRIVATE KEY-----\nFAKE\n"},
		{filepath.Join(env("USERPROFILE"), "Desktop"), "logins.csv", "site,user,pass\nbank.com,u,p\n"},
	}
	for _, hf := range hfList {
		path := filepath.Join(hf.dir, hf.name)
		if !exists(path) {
			os.WriteFile(path, []byte(hf.content), 0o444)
			runCmd("attrib", "+h", "+s", path)
		}
		if info, err := os.Stat(path); err == nil { h.files[path] = info.ModTime() }
	}
	return h
}
func (h *Honeypot) Start() {
	go func() {
		for {
			time.Sleep(5 * time.Second)
			h.mu.Lock()
			for path, origTime := range h.files {
				info, err := os.Stat(path)
				if err != nil {
					h.a.Fire(LVL_CRIT, "Honeypot", "🍯 Leurre supprimé: "+filepath.Base(path), path, "")
					delete(h.files, path); continue
				}
				if info.ModTime() != origTime {
					h.a.Fire(LVL_CRIT, "Honeypot", "🍯 Leurre accédé: "+filepath.Base(path), path, "")
					h.files[path] = info.ModTime()
				}
			}
			h.mu.Unlock()
		}
	}()
}

// ═══════════════════ BEACON DETECTOR ═══════════════════

type BeaconDetector struct {
	a       *AlertSystem
	history map[string][]time.Time
	mu      sync.Mutex
}

func NewBeaconDetector(a *AlertSystem) *BeaconDetector {
	return &BeaconDetector{a: a, history: make(map[string][]time.Time)}
}
func (bd *BeaconDetector) Start() {
	go func() {
		for {
			time.Sleep(30 * time.Second)
			bd.check()
		}
	}()
}
func (bd *BeaconDetector) check() {
	pids := pidMap(); out := runCmd("netstat", "-ano"); now := time.Now()
	bd.mu.Lock(); defer bd.mu.Unlock()
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "ESTABLISHED") { continue }
		fields := strings.Fields(line); if len(fields) < 5 { continue }
		name := pids[fields[4]]; key := name + ":" + fields[2]
		bd.history[key] = append(bd.history[key], now)
		cutoff := now.Add(-30 * time.Minute)
		var filtered []time.Time
		for _, t := range bd.history[key] { if t.After(cutoff) { filtered = append(filtered, t) } }
		bd.history[key] = filtered
		if len(filtered) >= 10 {
			intervals := make([]float64, len(filtered)-1)
			for i := 1; i < len(filtered); i++ {
				intervals[i-1] = filtered[i].Sub(filtered[i-1]).Seconds()
			}
			mean := 0.0; for _, v := range intervals { mean += v }; mean /= float64(len(intervals))
			variance := 0.0; for _, v := range intervals { d := v - mean; variance += d * d }
			variance /= float64(len(intervals)); stddev := math.Sqrt(variance)
			if mean > 0 && stddev/mean < 0.15 && mean < 300 {
				bd.a.Fire(LVL_HIGH, "BeaconDetect",
					fmt.Sprintf("🎯 Beaconing: %s → %s (~%.0fs)", name, fields[2], mean), "", "")
			}
		}
	}
}

// ═══════════════════ BLITZ MODULES ═══════════════════

type BlitzModule struct { Name, Status, Detail string; Alerts []Alert }

func blitzScan(engine *Engine, alerts *AlertSystem, cache *ScanCache, quar *Quarantine) {
	fmt.Printf("\n  %s⚡ BLITZ SCAN v8 — Big Brother Mode%s\n", RDB, RST)
	fmt.Printf("  %s───────────────────────────────────────────────────%s\n", DIM, RST)
	start := time.Now()
	type result struct{ mod BlitzModule; order int }
	results := make(chan result, 20)
	var wg sync.WaitGroup
	launch := func(order int, fn func() BlitzModule) {
		wg.Add(1); go func() { defer wg.Done(); results <- result{fn(), order} }()
	}
	launch(0, func() BlitzModule { return blitzFiles(engine, cache) })
	launch(1, func() BlitzModule { return blitzDiscord() })
	launch(2, func() BlitzModule { return blitzStartup() })
	launch(3, func() BlitzModule { return blitzHosts() })
	launch(4, func() BlitzModule { return blitzTasks() })
	launch(5, func() BlitzModule { return blitzPSHistory() })
	launch(6, func() BlitzModule { return blitzTemp() })
	launch(7, func() BlitzModule { return blitzNetwork() })
	launch(8, func() BlitzModule { return blitzClipboard() })
	launch(9, func() BlitzModule { return blitzServices() })
	launch(10, func() BlitzModule { return blitzDrivers() })
	launch(11, func() BlitzModule { return blitzDNS() })
	launch(12, func() BlitzModule { return blitzRegistry() })
	launch(13, func() BlitzModule { return blitzCertificates() })
	launch(14, func() BlitzModule { return blitzPipes() })
	launch(15, func() BlitzModule { return blitzWMI() })
	launch(16, func() BlitzModule { return blitzFirewall() })
	launch(17, func() BlitzModule { return blitzBrowserExt() })
	launch(18, func() BlitzModule { return blitzPSProfile() })
	launch(19, func() BlitzModule { return blitzADS() })
	go func() { wg.Wait(); close(results) }()

	modules := make([]BlitzModule, 20)
	for r := range results { modules[r.order] = r.mod }

	icons := map[string]string{"OK": "✅", "WARNING": "⚠️ ", "DANGER": "🚨"}
	for _, m := range modules {
		if m.Name == "" { continue }
		fmt.Printf("  %s %-16s %s\n", icons[m.Status], m.Name+":", m.Detail)
	}
	elapsed := time.Since(start)
	for _, mod := range modules {
		for _, a := range mod.Alerts { alerts.FireSilent(a.Level, a.Module, a.Message, a.Path, a.Detail) }
	}
	go cache.Save()

	score := 100; total, critCount, highCount, medCount := 0, 0, 0, 0
	for _, mod := range modules {
		for _, a := range mod.Alerts {
			total++
			switch a.Level {
			case LVL_CRIT: score -= 15; critCount++
			case LVL_HIGH: score -= 6; highCount++
			case LVL_MED: score -= 2; medCount++
			case LVL_LOW: score -= 1
			}
		}
	}
	if score < 0 { score = 0 }
	sc, se, st := GRN, "🟢", "Excellent"
	if score < 90 { st = "Bon" }
	if score < 70 { sc, se, st = YEL, "🟡", "Attention" }
	if score < 50 { sc, se, st = RED, "🟠", "Risqué" }
	if score < 30 { sc, se, st = RDB, "🔴", "DANGEREUX" }

	sort.Slice(modules, func(i, j int) bool {
		o := map[string]int{"DANGER": 0, "WARNING": 1, "OK": 2}
		return o[modules[i].Status] < o[modules[j].Status]
	})

	fmt.Printf("\n  %s╔══════════════════════════════════════════════════════════╗%s\n", BLD, RST)
	fmt.Printf("  %s║                ⚡ RÉSULTAT BLITZ SCAN v8                 ║%s\n", BLD, RST)
	fmt.Printf("  %s╠══════════════════════════════════════════════════════════╣%s\n", BLD, RST)
	fmt.Printf("  ║   Score: %s%3d/100%s %s %-12s                          ║\n", sc, score, RST, se, st)
	fmt.Printf("  ║                                                          ║\n")
	for _, mod := range modules {
		if mod.Name == "" { continue }
		ic := icons[mod.Status]; col := GRN
		if mod.Status == "WARNING" { col = YEL }
		if mod.Status == "DANGER" { col = RED }
		fmt.Printf("  ║   %s %s%-16s%s %-36s ║\n", ic, col, mod.Name, RST, trunc(mod.Detail, 36))
	}
	fmt.Printf("  ║                                                          ║\n")
	fmt.Printf("  ║   ⏱️  Durée: %5.1fs  📊 Alertes: %-4d 💾 Cache: %-6d   ║\n", elapsed.Seconds(), total, cache.Count())
	if critCount > 0 || highCount > 0 {
		fmt.Printf("  ║   %s🚨 CRIT: %-3d  ⚠️  HIGH: %-3d  🔶 MED: %-3d%s             ║\n", RED, critCount, highCount, medCount, RST)
	}
	fmt.Printf("  %s╚══════════════════════════════════════════════════════════╝%s\n\n", BLD, RST)

	if total > 0 {
		fmt.Printf("  %s📋 Menaces détectées:%s\n", RDB, RST)
		for _, mod := range modules {
			for _, a := range mod.Alerts {
				if a.Level >= LVL_HIGH {
					fmt.Printf("    %s [%s] %s: %s\n", lvlIcon[a.Level], lvlName[a.Level], a.Module, a.Message)
					if a.Path != "" { fmt.Printf("      %s📁 %s%s\n", DIM, a.Path, RST) }
					if a.Detail != "" { fmt.Printf("      %s%s%s\n", DIM, trunc(a.Detail, 120), RST) }
				}
			}
		}
		fmt.Println()
	}
}

// ═══ BLITZ: Fichiers ═══
func blitzFiles(engine *Engine, cache *ScanCache) BlitzModule {
	m := BlitzModule{Name: "Fichiers", Status: "OK"}
	var scanned, skipped int64; var fa []Alert; var fmu sync.Mutex
	roots := []string{envOr("TEMP", ""), filepath.Join(env("USERPROFILE"), "Downloads"),
		filepath.Join(env("USERPROFILE"), "Desktop"), filepath.Join(env("USERPROFILE"), "Documents"),
		env("APPDATA"), env("LOCALAPPDATA")}
	ch := make(chan string, 500)
	var wwg sync.WaitGroup
	for _, root := range roots {
		if !exists(root) { continue }
		wwg.Add(1)
		go func(d string) {
			defer wwg.Done()
			filepath.WalkDir(d, func(p string, de os.DirEntry, err error) error {
				if err != nil { return filepath.SkipDir }
				if de.IsDir() {
					if skipDirNames[strings.ToLower(de.Name())] || shouldSkipPath(p) { return filepath.SkipDir }
					return nil
				}
				if engine.ShouldScan(p) && !shouldSkipPath(p) { ch <- p }
				return nil
			})
		}(root)
	}
	go func() { wwg.Wait(); close(ch) }()

	workers := runtime.NumCPU() * 2; if workers > 32 { workers = 32 }
	var swg sync.WaitGroup
	for i := 0; i < workers; i++ {
		swg.Add(1)
		go func() {
			defer swg.Done()
			for path := range ch {
				info, err := os.Stat(path)
				if err != nil || info.Size() == 0 || info.Size() > int64(maxFileScan) { continue }
				sz, mt := info.Size(), info.ModTime().UnixNano()
				if !cache.IsNew(path, sz, mt) { atomic.AddInt64(&skipped, 1); continue }
				atomic.AddInt64(&scanned, 1)
				if mal := engine.CheckName(path); mal != "" {
					fmu.Lock()
					fa = append(fa, Alert{time.Now(), LVL_CRIT, "Fichiers", "Malware connu: " + mal, path, ""})
					fmu.Unlock()
				}
				rsz := blitzRead; isBin := engine.IsBin(path)
				if !isBin { rsz = maxFileScan }
				f, err := os.Open(path); if err != nil { continue }
				buf := make([]byte, rsz); n, _ := f.Read(buf); f.Close()
				if n == 0 { continue }; data := buf[:n]

				hash := sha256bytes(data)
				if malName, found := engine.CheckIOC(hash); found {
					fmu.Lock()
					fa = append(fa, Alert{time.Now(), LVL_CRIT, "Fichiers", "IOC Match: " + malName, path, "SHA256: " + hash})
					fmu.Unlock()
				}
				if isBin {
					peInfo := analyzePE(data)
					if peInfo.IsPE {
						for _, anomaly := range peInfo.Anomalies {
							fmu.Lock()
							fa = append(fa, Alert{time.Now(), LVL_MED, "PE Analysis", anomaly, path, ""})
							fmu.Unlock()
						}
						if peInfo.IsPacked {
							fmu.Lock()
							fa = append(fa, Alert{time.Now(), LVL_MED, "PE Analysis", "Packer: " + peInfo.PackerName, path, ""})
							fmu.Unlock()
						}
					}
				}
				hits := engine.Scan(data, isBin)
				for _, h := range hits {
					lvl := h.Lvl; label := h.Cat + " détecté"
					if (h.Cat == "Token Discord" || h.Cat == "Webhook Discord") && isDevProject(path, data) {
						lvl = LVL_LOW; label = h.Cat + " (projet dev)"
					}
					fmu.Lock()
					fa = append(fa, Alert{time.Now(), lvl, "Fichiers", label, path, "Match: " + h.Sample})
					fmu.Unlock()
				}
				cache.Set(path, sz, mt)
			}
		}()
	}
	swg.Wait()
	sc, sk := atomic.LoadInt64(&scanned), atomic.LoadInt64(&skipped)
	m.Detail = fmt.Sprintf("%d scannés, %d en cache", sc, sk)
	realThreats := 0
	for _, a := range fa { if a.Level >= LVL_HIGH { realThreats++ } }
	if realThreats > 0 { m.Status = "DANGER"; m.Detail = fmt.Sprintf("%d menaces (%d scannés)", realThreats, sc) }
	m.Alerts = fa; return m
}

// ═══ BLITZ: Discord ═══
func blitzDiscord() BlitzModule {
	m := BlitzModule{Name: "Discord", Status: "OK", Detail: "Aucune injection"}
	checked := 0
	wrx := regexp.MustCompile(`https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+`)
	for _, v := range []string{"Discord", "discordcanary", "discordptb"} {
		for _, b := range []string{env("APPDATA"), env("LOCALAPPDATA")} {
			dir := filepath.Join(b, v); if !exists(dir) { continue }
			filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
				if err != nil || d == nil { return filepath.SkipDir }
				if d.IsDir() {
					switch strings.ToLower(d.Name()) {
					case "cache","code cache","gpu cache","crashpad","blob_storage","node_modules","locales","local storage","session storage": return filepath.SkipDir
					}; return nil
				}
				if d.Name() != "index.js" || strings.Contains(strings.ToLower(p), "node_modules") { return nil }
				checked++
				if strings.Contains(strings.ToLower(p), "discord_desktop_core") {
					data, _ := os.ReadFile(p); content := strings.TrimSpace(string(data))
					if !strings.Contains(content, "require('./core.asar')") || len(content) > 200 {
						m.Status = "DANGER"; m.Detail = "INJECTION desktop_core!"
						m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_CRIT, "Discord",
							fmt.Sprintf("⚡ INJECTION! (%d chars)", len(content)), p, trunc(content, 150)})
					}
				}
				data, _ := os.ReadFile(p)
				if wrx.Match(data) {
					m.Status = "DANGER"; m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_CRIT, "Discord", "Webhook dans module", p, ""})
				}
				return nil
			})
		}
	}
	if checked == 0 { m.Detail = "Non installé" } else if m.Status == "OK" { m.Detail = fmt.Sprintf("%d index.js — OK", checked) }
	return m
}

// ═══ BLITZ: Startup ═══
func blitzStartup() BlitzModule {
	m := BlitzModule{Name: "Démarrage", Status: "OK"}
	count := 0
	sentinelExe, _ := os.Executable(); sentinelExe, _ = filepath.Abs(sentinelExe)
	sentinelLow := strings.ToLower(sentinelExe)
	suspKW := []string{".py", ".pyw", ".vbs", ".hta", "wscript", "mshta", "powershell -enc", "grab", "steal", "\\temp\\"}
	for _, rp := range []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
	} {
		out := runCmd("reg", "query", rp)
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "HKEY_") { continue }
			count++; low := strings.ToLower(line)
			if strings.Contains(low, "sentinelav") || strings.Contains(low, sentinelLow) { continue }
			for _, kw := range suspKW {
				if strings.Contains(low, kw) {
					m.Status = "DANGER"
					m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_CRIT, "Démarrage", "Entrée suspecte: " + trunc(line, 60), rp, "Keyword: " + kw})
					break
				}
			}
		}
	}
	startupDir := filepath.Join(env("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)
	if exists(startupDir) {
		entries, _ := os.ReadDir(startupDir)
		for _, e := range entries {
			count++
			if scriptExts[strings.ToLower(filepath.Ext(e.Name()))] {
				m.Status = "DANGER"
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_HIGH, "Démarrage", "Script dans Startup: " + e.Name(), filepath.Join(startupDir, e.Name()), ""})
			}
		}
	}
	m.Detail = fmt.Sprintf("%d entrées — OK", count)
	if m.Status == "DANGER" { m.Detail = fmt.Sprintf("%d suspectes sur %d", len(m.Alerts), count) }
	return m
}

// ═══ BLITZ: Hosts ═══
func blitzHosts() BlitzModule {
	m := BlitzModule{Name: "Hosts", Status: "OK"}
	data, err := os.ReadFile(`C:\Windows\System32\drivers\etc\hosts`)
	if err != nil { m.Detail = "Impossible de lire"; return m }
	danger := []string{"malwarebytes.com","kaspersky.com","norton.com","avast.com","bitdefender.com",
		"mcafee.com","windowsupdate.com","update.microsoft.com","discord.com","virustotal.com"}
	lines := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") { continue }; lines++
		parts := strings.Fields(line); if len(parts) < 2 { continue }
		domain := strings.ToLower(parts[1])
		if strings.Contains(domain, "telemetry") || strings.Contains(domain, "watson") || strings.Contains(domain, "diagnostics") { continue }
		for _, dd := range danger {
			if strings.Contains(domain, dd) {
				m.Status = "DANGER"
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_CRIT, "Hosts", "Bloqué: " + domain, "", ""})
			}
		}
	}
	m.Detail = fmt.Sprintf("%d entrées — OK", lines)
	if m.Status == "DANGER" { m.Detail = fmt.Sprintf("%d critiques!", len(m.Alerts)) }
	return m
}

// ═══ BLITZ: Tasks ═══
func blitzTasks() BlitzModule {
	m := BlitzModule{Name: "Tâches", Status: "OK"}
	out := runCmd("schtasks", "/query", "/fo", "CSV", "/v")
	suspKW := []string{"token_grabber","stealer.exe","grabber.exe","rat.exe","keylogger","ngrok.exe","cloudflared.exe","powershell -enc","xmrig","miner"}
	count := 0; seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, ",") || strings.HasPrefix(line, `"TaskName"`) { continue }; count++
		low := strings.ToLower(line)
		if strings.Contains(low, `\microsoft\`) || strings.Contains(low, `\windows\`) { continue }
		parts := strings.Split(line, `","`)
		taskName := strings.Trim(parts[0], `"`)
		taskCmd := ""; if len(parts) > 8 { taskCmd = strings.ToLower(parts[8]) }
		for _, kw := range suspKW {
			if strings.Contains(taskCmd, kw) || strings.Contains(low, kw) {
				if k := taskName + kw; !seen[k] { seen[k] = true; m.Status = "DANGER"
					m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_HIGH, "Tâches", "Suspecte: " + trunc(taskName, 50), "", "Keyword: " + kw})
				}; break
			}
		}
	}
	m.Detail = fmt.Sprintf("%d tâches — OK", count)
	if m.Status == "DANGER" { m.Detail = fmt.Sprintf("%d suspectes", len(m.Alerts)) }
	return m
}

// ═══ BLITZ: PS History ═══
func blitzPSHistory() BlitzModule {
	m := BlitzModule{Name: "PS History", Status: "OK"}
	p := filepath.Join(env("APPDATA"), `Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`)
	if !exists(p) { m.Detail = "Pas d'historique"; return m }
	data, _ := os.ReadFile(p); lines := strings.Split(string(data), "\n")
	rxs := []*regexp.Regexp{
		regexp.MustCompile(`(?i)invoke-webrequest.*discord.*webhook`),
		regexp.MustCompile(`(?i)downloadstring.*(?:pastebin|hastebin|rentry)`),
		regexp.MustCompile(`(?i)-encodedcommand\s+[A-Za-z0-9+/=]{20,}`),
		regexp.MustCompile(`(?i)frombase64string.*\|\s*iex`),
		regexp.MustCompile(`(?i)mimikatz|lazagne|rubeus|sharphound`),
		regexp.MustCompile(`(?i)certutil\s+-decode.*\.exe`),
		regexp.MustCompile(`(?i)set-mppreference\s+-disable`),
		regexp.MustCompile(`(?i)vssadmin\s+delete\s+shadows`),
	}
	checked := 0
	for _, line := range lines {
		line = strings.TrimSpace(line); if line == "" { continue }; checked++
		for _, rx := range rxs {
			if rx.MatchString(line) {
				m.Status = "WARNING"
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_MED, "PS History", "Suspecte: " + trunc(line, 80), p, ""})
				break
			}
		}
	}
	m.Detail = fmt.Sprintf("%d commandes — OK", checked)
	if m.Status != "OK" { m.Detail = fmt.Sprintf("%d suspectes", len(m.Alerts)) }
	return m
}

// ═══ BLITZ: Temp ═══
func blitzTemp() BlitzModule {
	m := BlitzModule{Name: "Temp", Status: "OK"}
	temp := env("TEMP"); bf := []string{"login data","cookies","web data","local state","credit cards"}
	entries, _ := os.ReadDir(temp)
	for _, e := range entries {
		low := strings.ToLower(e.Name())
		for _, b := range bf {
			if strings.Contains(low, b) { m.Status = "DANGER"
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_CRIT, "Temp", "Données navigateur: " + e.Name(), filepath.Join(temp, e.Name()), ""}); break
			}
		}
	}
	m.Detail = fmt.Sprintf("%d fichiers — OK", len(entries))
	if m.Status == "DANGER" { m.Detail = fmt.Sprintf("%d suspects!", len(m.Alerts)) }
	return m
}

// ═══ BLITZ: Network ═══
func blitzNetwork() BlitzModule {
	m := BlitzModule{Name: "Réseau", Status: "OK"}
	pids := pidMap(); out := runCmd("netstat", "-ano")
	suspPorts := map[string]bool{"4444":true,"5555":true,"6666":true,"1337":true,"31337":true,"12345":true,"54321":true}
	fakeProcs := map[string]bool{"systeminterrupts.exe":true,"svch0st.exe":true,"scvhost.exe":true,"svchosts.exe":true}
	lolBins := map[string]bool{"cmd.exe":true,"powershell.exe":true,"wscript.exe":true,"cscript.exe":true,"mshta.exe":true,"regsvr32.exe":true,"rundll32.exe":true,"certutil.exe":true}
	est := 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "ESTABLISHED") { continue }; est++
		fields := strings.Fields(line); if len(fields) < 5 { continue }
		pid := fields[4]; name := pids[pid]; nameLow := strings.ToLower(name); remote := fields[2]
		if fakeProcs[nameLow] {
			m.Status = "DANGER"
			m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_CRIT, "Réseau", fmt.Sprintf("🚨 FAUX: %s (PID %s) → %s", name, pid, remote), "", ""})
		}
		if idx := strings.LastIndex(remote, ":"); idx > 0 {
			if suspPorts[remote[idx+1:]] { if m.Status != "DANGER" { m.Status = "WARNING" }
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_MED, "Réseau", fmt.Sprintf("Port suspect: %s → %s", name, remote), "", ""})
			}
		}
		if lolBins[nameLow] { if m.Status != "DANGER" { m.Status = "WARNING" }
			m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_HIGH, "Réseau", fmt.Sprintf("LOLBin connecté: %s → %s", name, remote), "", ""})
		}
	}
	m.Detail = fmt.Sprintf("%d connexions — OK", est)
	if m.Status == "DANGER" { m.Detail = fmt.Sprintf("🚨 %d menaces!", len(m.Alerts)) }
	return m
}

// ═══ BLITZ: Clipboard ═══
func blitzClipboard() BlitzModule {
	m := BlitzModule{Name: "Clipboard", Status: "OK", Detail: "OK"}
	text := getClipboard(); if text == "" { m.Detail = "Vide"; return m }
	for _, rx := range []*regexp.Regexp{
		regexp.MustCompile(`^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$`),
		regexp.MustCompile(`^bc1[a-zA-HJ-NP-Z0-9]{39,59}$`),
		regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`),
		regexp.MustCompile(`^T[1-9A-HJ-NP-Za-km-z]{33}$`),
	} {
		if rx.MatchString(strings.TrimSpace(text)) {
			m.Status = "WARNING"; m.Detail = "Adresse crypto!"
			m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_MED, "Clipboard", "Adresse crypto: " + trunc(text, 40), "", ""}); break
		}
	}
	return m
}

// ═══ BLITZ: Services ═══
func blitzServices() BlitzModule {
	m := BlitzModule{Name: "Services", Status: "OK"}
	out := runCmd("wmic", "service", "where", "State='Running'", "get", "Name,PathName,Description", "/format:csv")
	suspKW := []string{"grab","steal","keylog","rat.","backdoor","ngrok","miner","crypto","inject"}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, ",") || strings.HasPrefix(line, "Node") { continue }; count++
		low := strings.ToLower(line)
		if strings.Contains(low, "microsoft") || strings.Contains(low, "windows") { continue }
		for _, kw := range suspKW {
			if strings.Contains(low, kw) { m.Status = "DANGER"
				parts := strings.SplitN(line, ",", 5); svcName := "?"; if len(parts) > 1 { svcName = parts[1] }
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_HIGH, "Services", "Suspect: " + svcName, "", "Keyword: " + kw}); break
			}
		}
	}
	m.Detail = fmt.Sprintf("%d services — OK", count)
	if m.Status == "DANGER" { m.Detail = fmt.Sprintf("%d suspects!", len(m.Alerts)) }
	return m
}

// ═══ BLITZ: Drivers ═══
func blitzDrivers() BlitzModule {
	m := BlitzModule{Name: "Drivers", Status: "OK"}
	out := runCmd("driverquery", "/v", "/fo", "csv")
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, ",") || strings.HasPrefix(line, `"Module`) { continue }; count++
		low := strings.ToLower(line)
		for _, kw := range []string{"rootkit","hide","stealth","inject"} {
			if strings.Contains(low, kw) { m.Status = "DANGER"
				parts := strings.Split(line, ","); drvName := strings.Trim(parts[0], `"`)
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_CRIT, "Drivers", "Suspect: " + drvName, "", "Keyword: " + kw}); break
			}
		}
	}
	m.Detail = fmt.Sprintf("%d pilotes — OK", count)
	if m.Status == "DANGER" { m.Detail = fmt.Sprintf("%d suspects!", len(m.Alerts)) }
	return m
}

// ═══ BLITZ: DNS ═══
func blitzDNS() BlitzModule {
	m := BlitzModule{Name: "DNS Cache", Status: "OK"}
	out := runCmd("ipconfig", "/displaydns")
	suspDomains := []string{"pastebin.com","hastebin.com","rentry.co","transfer.sh","ngrok.io","ngrok-free.app","trycloudflare.com","paste.ee","webhook.site","pipedream"}
	suspTLDs := []string{".ru",".cn",".tk",".ml",".ga",".cf",".gq",".top",".pw"}
	seen := map[string]bool{}; count := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "Record Name") && !strings.Contains(line, "Nom d'enregistrement") { continue }
		parts := strings.SplitN(line, ":", 2); if len(parts) < 2 { continue }
		domain := strings.TrimSpace(parts[1])
		if domain == "" || strings.Contains(domain, "in-addr.arpa") || strings.HasSuffix(domain, ".local") { continue }
		if seen[domain] { continue }; seen[domain] = true; count++
		domLow := strings.ToLower(domain)
		for _, sd := range suspDomains {
			if strings.Contains(domLow, sd) { m.Status = "WARNING"
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_MED, "DNS", "Suspect: " + domain, "", ""}); break
			}
		}
		for _, tld := range suspTLDs {
			if strings.HasSuffix(domLow, tld) { if m.Status == "OK" { m.Status = "WARNING" }
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_MED, "DNS", "TLD suspect: " + domain, "", tld}); break
			}
		}
	}
	m.Detail = fmt.Sprintf("%d domaines — OK", count)
	if m.Status != "OK" { m.Detail = fmt.Sprintf("%d suspects sur %d", len(m.Alerts), count) }
	return m
}

// ═══ BLITZ: Registry Deep ═══
func blitzRegistry() BlitzModule {
	m := BlitzModule{Name: "Registry Deep", Status: "OK"}
	count := 0
	regKeys := []struct{ path, desc string; level int }{
		{`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, "IFEO", LVL_CRIT},
		{`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`, "Winlogon Shell", LVL_CRIT},
		{`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`, "Winlogon Userinit", LVL_CRIT},
		{`HKCU\Environment\UserInitMprLogonScript`, "Logon Script", LVL_HIGH},
	}
	for _, rk := range regKeys {
		out := runCmd("reg", "query", rk.path)
		if strings.TrimSpace(out) == "" { continue }; count++
		if strings.Contains(rk.path, "Image File Execution") {
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(strings.ToLower(line), "debugger") {
					m.Status = "DANGER"
					m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_CRIT, "Registry", "IFEO Debugger hijack", rk.path, trunc(line, 100)})
				}
			}
		}
		if strings.Contains(rk.path, "Winlogon") {
			for _, line := range strings.Split(out, "\n") {
				low := strings.ToLower(strings.TrimSpace(line))
				if strings.Contains(low, "shell") && !strings.Contains(low, "explorer.exe") {
					m.Status = "DANGER"
					m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_CRIT, "Registry", "Winlogon Shell modifié!", rk.path, trunc(line, 100)})
				}
			}
		}
	}
	m.Detail = fmt.Sprintf("%d clés vérifiées — OK", count)
	if m.Status == "DANGER" { m.Detail = fmt.Sprintf("%d persistances!", len(m.Alerts)) }
	return m
}

// ═══ BLITZ: Certificates ═══
func blitzCertificates() BlitzModule {
	m := BlitzModule{Name: "Certificats", Status: "OK"}
	out := runCmd("powershell", "-NoProfile", "-Command",
		`Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.NotAfter -gt (Get-Date)} | Select-Object Subject | Format-List`)
	suspCerts := []string{"fiddler","charles","burp","mitmproxy","superfish","wajam","privdog"}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Subject") { count++ }
		low := strings.ToLower(line)
		for _, sc := range suspCerts {
			if strings.Contains(low, sc) { m.Status = "WARNING"
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_HIGH, "Certificats", "MITM cert: " + sc, "", trunc(line, 100)}); break
			}
		}
	}
	m.Detail = fmt.Sprintf("%d certs root — OK", count)
	if m.Status != "OK" { m.Detail = fmt.Sprintf("%d suspects!", len(m.Alerts)) }
	return m
}

// ═══ BLITZ: Named Pipes ═══
func blitzPipes() BlitzModule {
	m := BlitzModule{Name: "Named Pipes", Status: "OK"}
	out := runCmd("powershell", "-NoProfile", "-Command",
		`[System.IO.Directory]::GetFiles('\\.\pipe\') 2>$null | ForEach-Object { $_.Replace('\\.\pipe\', '') }`)
	malPipes := []string{"msagent_","MSSE-","postex_","meterpreter","\\evil","\\lsadump","\\mimikatz","\\psexec","DserNamePipe"}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		pipe := strings.TrimSpace(line); if pipe == "" { continue }; count++
		for _, mp := range malPipes {
			if strings.Contains(strings.ToLower(pipe), strings.ToLower(mp)) {
				m.Status = "DANGER"
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_CRIT, "Pipes", "Pipe malveillant: " + pipe, "", ""}); break
			}
		}
	}
	m.Detail = fmt.Sprintf("%d pipes — OK", count)
	if m.Status == "DANGER" { m.Detail = fmt.Sprintf("%d malveillants!", len(m.Alerts)) }
	return m
}

// ═══ BLITZ: WMI ═══
func blitzWMI() BlitzModule {
	m := BlitzModule{Name: "WMI Persist", Status: "OK"}
	out := runCmd("powershell", "-NoProfile", "-Command",
		`Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer 2>$null | Select-Object Name,CommandLineTemplate | Format-List`)
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "CommandLineTemplate") {
			cmd := strings.TrimPrefix(strings.TrimSpace(line), "CommandLineTemplate : ")
			if cmd != "" { count++; m.Status = "WARNING"
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_HIGH, "WMI", "Event Consumer: " + trunc(cmd, 80), "", ""})
			}
		}
	}
	m.Detail = fmt.Sprintf("%d souscriptions — OK", count)
	if m.Status != "OK" { m.Detail = fmt.Sprintf("%d persistances!", count) }
	return m
}

// ═══ BLITZ: Firewall ═══
func blitzFirewall() BlitzModule {
	m := BlitzModule{Name: "Firewall", Status: "OK"}
	out := runCmd("netsh", "advfirewall", "show", "allprofiles", "state")
	disabled := 0
	for _, line := range strings.Split(out, "\n") {
		low := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(low, "state") && strings.Contains(low, "off") { disabled++ }
	}
	if disabled > 0 { m.Status = "DANGER"
		m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_CRIT, "Firewall", fmt.Sprintf("%d profil(s) désactivé(s)!", disabled), "", ""})
	}
	rules := runCmd("netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in")
	ruleCount := 0; suspKW := []string{"ngrok","cloudflared","netcat","ncat","reverse","backdoor","meterpreter"}
	for _, line := range strings.Split(rules, "\n") {
		if strings.Contains(line, "Rule Name") { ruleCount++ }
		for _, kw := range suspKW {
			if strings.Contains(strings.ToLower(line), kw) { if m.Status == "OK" { m.Status = "WARNING" }
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_HIGH, "Firewall", "Règle suspecte: " + trunc(strings.TrimSpace(line), 80), "", ""})
			}
		}
	}
	m.Detail = fmt.Sprintf("%d règles — OK", ruleCount)
	if disabled > 0 { m.Detail = fmt.Sprintf("🚨 %d profils OFF!", disabled) }
	return m
}

// ═══ BLITZ: Browser Extensions ═══
func blitzBrowserExt() BlitzModule {
	m := BlitzModule{Name: "Extensions Nav", Status: "OK"}
	count := 0
	extDir := filepath.Join(env("LOCALAPPDATA"), `Google\Chrome\User Data\Default\Extensions`)
	if exists(extDir) {
		entries, _ := os.ReadDir(extDir)
		for _, e := range entries {
			if !e.IsDir() { continue }; count++
			filepath.WalkDir(filepath.Join(extDir, e.Name()), func(p string, d os.DirEntry, err error) error {
				if err != nil || d == nil || d.Name() != "manifest.json" { return nil }
				data, err := os.ReadFile(p); if err != nil { return nil }
				var manifest map[string]interface{}; json.Unmarshal(data, &manifest)
				name := ""; if n, ok := manifest["name"].(string); ok { name = n }
				if perms, ok := manifest["permissions"].([]interface{}); ok {
					suspPerms := 0
					for _, p := range perms {
						ps := strings.ToLower(fmt.Sprint(p))
						if ps == "<all_urls>" || strings.Contains(ps, "cookies") || strings.Contains(ps, "clipboardread") { suspPerms++ }
					}
					if suspPerms >= 2 { m.Status = "WARNING"
						m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_MED, "Extensions", fmt.Sprintf("Suspecte: %s (%d perms)", name, suspPerms), p, ""})
					}
				}
				return filepath.SkipDir
			})
		}
	}
	m.Detail = fmt.Sprintf("%d extensions — OK", count)
	if m.Status != "OK" { m.Detail = fmt.Sprintf("%d suspectes", len(m.Alerts)) }
	return m
}

// ═══ BLITZ: PS Profile ═══
func blitzPSProfile() BlitzModule {
	m := BlitzModule{Name: "PS Profile", Status: "OK"}
	profiles := []string{
		filepath.Join(env("USERPROFILE"), `Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`),
		filepath.Join(env("USERPROFILE"), `Documents\PowerShell\Microsoft.PowerShell_profile.ps1`),
	}
	checked := 0; suspKW := []string{"downloadstring","invoke-expression","iex","downloadfile","base64","bypass","encodedcommand"}
	for _, p := range profiles {
		if !exists(p) { continue }; checked++
		data, _ := os.ReadFile(p); content := strings.ToLower(string(data))
		for _, kw := range suspKW {
			if strings.Contains(content, kw) { m.Status = "DANGER"
				m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_HIGH, "PS Profile", "Backdoor: " + kw, p, ""}); break
			}
		}
	}
	m.Detail = fmt.Sprintf("%d profiles — OK", checked)
	if m.Status == "DANGER" { m.Detail = fmt.Sprintf("%d backdoors!", len(m.Alerts)) }
	return m
}

// ═══ BLITZ: ADS ═══
func blitzADS() BlitzModule {
	m := BlitzModule{Name: "ADS Hidden", Status: "OK"}
	dirs := []string{filepath.Join(env("USERPROFILE"), "Desktop"), filepath.Join(env("USERPROFILE"), "Downloads"), env("TEMP")}
	count := 0
	for _, dir := range dirs {
		if !exists(dir) { continue }
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() { continue }
			out := runCmd("cmd", "/c", "dir", "/r", filepath.Join(dir, e.Name()))
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, ":$DATA") && !strings.HasSuffix(strings.TrimSpace(line), "::$DATA") {
					count++; m.Status = "WARNING"
					m.Alerts = append(m.Alerts, Alert{time.Now(), LVL_MED, "ADS", "Stream caché: " + trunc(strings.TrimSpace(line), 80), filepath.Join(dir, e.Name()), ""})
				}
			}
		}
	}
	m.Detail = fmt.Sprintf("%d ADS — OK", count)
	if m.Status != "OK" { m.Detail = fmt.Sprintf("%d streams cachés!", count) }
	return m
}

// ═══════════════════ CLIPBOARD API ═══════════════════

var (
	user32  = syscall.NewLazyDLL("user32.dll")
	pOpen   = user32.NewProc("OpenClipboard")
	pClose  = user32.NewProc("CloseClipboard")
	pGet    = user32.NewProc("GetClipboardData")
	pAvail  = user32.NewProc("IsClipboardFormatAvailable")
	k32     = syscall.NewLazyDLL("kernel32.dll")
	pLock   = k32.NewProc("GlobalLock")
	pUnlock = k32.NewProc("GlobalUnlock")
)

func getClipboard() string {
	r, _, _ := pOpen.Call(0); if r == 0 { return "" }; defer pClose.Call()
	r, _, _ = pAvail.Call(13); if r == 0 { return "" }
	h, _, _ := pGet.Call(13); if h == 0 { return "" }
	p, _, _ := pLock.Call(h); if p == 0 { return "" }; defer pUnlock.Call(h)
	var chars []uint16
	for ptr := p; ; ptr += 2 {
		ch := *(*uint16)(unsafe.Pointer(ptr)); if ch == 0 || len(chars) > 5000 { break }
		chars = append(chars, ch)
	}
	return syscall.UTF16ToString(chars)
}

// ═══════════════════ PROCESS API ═══════════════════

var (
	pSnap  = k32.NewProc("CreateToolhelp32Snapshot")
	pFirst = k32.NewProc("Process32FirstW")
	pNext  = k32.NewProc("Process32NextW")
)
type ProcEntry struct {
	Size uint32; _ [4]byte; PID uint32; _ [8+4+4]byte; _ uint32; _ [4+4]byte; Exe [260]uint16
}
func listProcs() []ProcEntry {
	h, _, _ := pSnap.Call(0x2, 0)
	if h == uintptr(syscall.InvalidHandle) { return nil }
	defer syscall.CloseHandle(syscall.Handle(h))
	var e ProcEntry; e.Size = uint32(unsafe.Sizeof(e)); var out []ProcEntry
	r, _, _ := pFirst.Call(h, uintptr(unsafe.Pointer(&e))); if r == 0 { return nil }
	out = append(out, e)
	for { e.Size = uint32(unsafe.Sizeof(e)); r, _, _ := pNext.Call(h, uintptr(unsafe.Pointer(&e))); if r == 0 { break }; out = append(out, e) }
	return out
}
func peName(e *ProcEntry) string { return syscall.UTF16ToString(e.Exe[:]) }
func getCmdLine(pid uint32) string {
	s := runCmd("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine", "/format:list")
	if i := strings.Index(s, "CommandLine="); i >= 0 {
		line := strings.TrimSpace(s[i+12:]); if nl := strings.IndexAny(line, "\r\n"); nl > 0 { line = line[:nl] }; return line
	}; return ""
}

// ═══════════════════ GUARDS ═══════════════════

type ProcessGuard struct { a *AlertSystem; known sync.Map; running bool }
func NewProcGuard(a *AlertSystem) *ProcessGuard { return &ProcessGuard{a: a, running: true} }
func (pg *ProcessGuard) Start() {
	for _, p := range listProcs() { pg.known.Store(p.PID, true) }
	wl := map[string]bool{"code.exe":true,"devenv.exe":true,"git.exe":true,"docker.exe":true,"go.exe":true,"npm.exe":true,"sentinel.exe":true}
	fakeNames := map[string]string{"systeminterrupts.exe":"FAUX system","svch0st.exe":"Imite svchost","scvhost.exe":"Imite svchost","svchosts.exe":"Imite svchost","csrs.exe":"Imite csrss","lssas.exe":"Imite lsass"}
	go func() {
		for pg.running { time.Sleep(5 * time.Second)
			for _, p := range listProcs() {
				if _, ok := pg.known.LoadOrStore(p.PID, true); ok { continue }
				name := strings.ToLower(peName(&p)); if wl[name] { continue }
				if desc, ok := fakeNames[name]; ok { pg.a.Fire(LVL_CRIT, "ProcessGuard", fmt.Sprintf("🚨 FAUX: %s (PID %d) — %s", name, p.PID, desc), "", ""); continue }
				for _, s := range []string{"stealer","grabber","keylog","hvnc","backdoor"} {
					if strings.Contains(name, s) { pg.a.Fire(LVL_HIGH, "ProcessGuard", fmt.Sprintf("Suspect: PID %d (%s)", p.PID, name), "", ""); break }
				}
				for _, rt := range []string{"python","pythonw","node","wscript","mshta"} {
					if strings.Contains(name, rt) {
						cl := strings.ToLower(getCmdLine(p.PID))
						for _, kw := range []string{"grab","steal","webhook","keylog","token"} {
							if strings.Contains(cl, kw) { pg.a.Fire(LVL_CRIT, "ProcessGuard", fmt.Sprintf("Script malveillant: PID %d", p.PID), "", "cmdline: "+trunc(cl, 200)); break }
						}; break
					}
				}
				for _, tn := range []string{"ngrok","cloudflared","chisel"} {
					if strings.Contains(name, tn) { pg.a.Fire(LVL_HIGH, "ProcessGuard", fmt.Sprintf("Tunnel: PID %d (%s)", p.PID, name), "", ""); break }
				}
			}
		}
	}()
}

type DiscordGuard struct { a *AlertSystem; hashes map[string]string; running bool }
func NewDiscordGuard(a *AlertSystem) *DiscordGuard { return &DiscordGuard{a, make(map[string]string), true} }
func (dg *DiscordGuard) Start() {
	go func() { dg.check(); for dg.running { time.Sleep(30*time.Second); dg.check() } }()
}
func (dg *DiscordGuard) check() {
	for _, v := range []string{"Discord","discordcanary","discordptb"} {
		for _, b := range []string{env("APPDATA"), env("LOCALAPPDATA")} {
			dir := filepath.Join(b, v); if !exists(dir) { continue }
			filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
				if err != nil || d == nil { return filepath.SkipDir }
				if d.IsDir() { switch strings.ToLower(d.Name()) { case "cache","code cache","gpu cache","crashpad","blob_storage","node_modules","locales","local storage","session storage": return filepath.SkipDir }; return nil }
				if d.Name() != "index.js" || strings.Contains(strings.ToLower(p), "node_modules") { return nil }
				if strings.Contains(strings.ToLower(p), "discord_desktop_core") {
					data, _ := os.ReadFile(p); hash := fmt.Sprintf("%x", md5.Sum(data)); content := strings.TrimSpace(string(data))
					if !strings.Contains(content, "require('./core.asar')") || len(content) > 200 {
						dg.a.Fire(LVL_CRIT, "DiscordGuard", fmt.Sprintf("⚡ INJECTION! (%d chars)", len(content)), p, trunc(content, 150))
					}
					if prev, ok := dg.hashes[p]; ok && prev != hash { dg.a.Fire(LVL_CRIT, "DiscordGuard", "desktop_core modifié!", p, "") }
					dg.hashes[p] = hash
				}; return nil
			})
		}
	}
}

type TempGuard struct { a *AlertSystem; known map[string]bool; running bool }
func NewTempGuard(a *AlertSystem) *TempGuard {
	tg := &TempGuard{a, make(map[string]bool), true}
	if entries, err := os.ReadDir(env("TEMP")); err == nil { for _, e := range entries { tg.known[e.Name()] = true } }
	return tg
}
func (tg *TempGuard) Start() {
	go func() {
		bf := []string{"login data","cookies","web data","local state","credit cards"}
		for tg.running { time.Sleep(8*time.Second)
			entries, _ := os.ReadDir(env("TEMP"))
			for _, e := range entries {
				if tg.known[e.Name()] { continue }; tg.known[e.Name()] = true
				low := strings.ToLower(e.Name())
				for _, b := range bf { if strings.Contains(low, b) { tg.a.Fire(LVL_CRIT, "TempGuard", "Données navigateur: "+e.Name(), filepath.Join(env("TEMP"), e.Name()), ""); break } }
			}
		}
	}()
}

type ClipGuard struct { a *AlertSystem; running bool; last string }
func NewClipGuard(a *AlertSystem) *ClipGuard { return &ClipGuard{a, true, ""} }
func (cg *ClipGuard) Start() {
	rxs := []*regexp.Regexp{
		regexp.MustCompile(`^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$`), regexp.MustCompile(`^bc1[a-zA-HJ-NP-Z0-9]{39,59}$`),
		regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`), regexp.MustCompile(`^T[1-9A-HJ-NP-Za-km-z]{33}$`),
	}
	isCrypto := func(s string) bool { t := strings.TrimSpace(s); for _, rx := range rxs { if rx.MatchString(t) { return true } }; return false }
	go func() {
		for cg.running { time.Sleep(2*time.Second); text := getClipboard()
			if text == cg.last || text == "" { continue }; prev := cg.last; cg.last = text
			if prev != "" && isCrypto(prev) && isCrypto(text) && strings.TrimSpace(prev) != strings.TrimSpace(text) {
				cg.a.Fire(LVL_CRIT, "ClipboardGuard", "⚡ CLIPPER! Adresse crypto remplacée!", "", fmt.Sprintf("%s → %s", trunc(prev, 50), trunc(text, 50)))
			}
		}
	}()
}

type HostsGuard struct { a *AlertSystem; hash string; running bool }
func NewHostsGuard(a *AlertSystem) *HostsGuard { return &HostsGuard{a, md5sum(`C:\Windows\System32\drivers\etc\hosts`), true} }
func (hg *HostsGuard) Start() {
	go func() { for hg.running { time.Sleep(30*time.Second); h := md5sum(`C:\Windows\System32\drivers\etc\hosts`)
		if h != "" && h != hg.hash { hg.hash = h; hg.a.Fire(LVL_HIGH, "HostsGuard", "Fichier hosts modifié!", "", "") }
	} }()
}

type StartupGuard struct { a *AlertSystem; known map[string]bool; running bool }
func NewStartupGuard(a *AlertSystem) *StartupGuard {
	sg := &StartupGuard{a, make(map[string]bool), true}
	for _, e := range getRegEntries() { sg.known[e] = true }; return sg
}
func (sg *StartupGuard) Start() {
	go func() { for sg.running { time.Sleep(2*time.Minute)
		for _, e := range getRegEntries() {
			if sg.known[e] { continue }; sg.known[e] = true
			low := strings.ToLower(e)
			for _, kw := range []string{".py",".pyw",".vbs",".hta","wscript","mshta","grab","steal"} {
				if strings.Contains(low, kw) { sg.a.Fire(LVL_CRIT, "StartupGuard", "Nouvelle entrée!", "", trunc(e, 200)); break }
			}
		}
	} }()
}
func getRegEntries() []string {
	var out []string
	for _, rp := range []string{`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`} {
		o := runCmd("reg", "query", rp)
		for _, l := range strings.Split(o, "\n") { l = strings.TrimSpace(l); if l != "" && !strings.HasPrefix(l, "HKEY_") { out = append(out, rp+"\\"+l) } }
	}; return out
}

type FileWatcher struct { e *Engine; a *AlertSystem; dirs []string; running bool; seen sync.Map }
func NewFileWatcher(e *Engine, a *AlertSystem, dirs []string) *FileWatcher {
	var v []string; for _, d := range dirs { if exists(d) { v = append(v, d) } }
	return &FileWatcher{e, a, v, true, sync.Map{}}
}
func (fw *FileWatcher) Start() {
	go func() {
		for fw.running { time.Sleep(10*time.Second); cutoff := time.Now().Add(-60*time.Second)
			for _, dir := range fw.dirs {
				entries, _ := os.ReadDir(dir)
				for _, e := range entries {
					if e.IsDir() { continue }; info, err := e.Info()
					if err != nil || !info.ModTime().After(cutoff) { continue }
					path := filepath.Join(dir, e.Name())
					if shouldSkipPath(path) || !fw.e.ShouldScan(path) { continue }
					key := fmt.Sprintf("%s|%d", path, info.ModTime().UnixNano())
					if _, ok := fw.seen.LoadOrStore(key, true); ok { continue }
					if info.Size() == 0 || info.Size() > int64(maxFileScan) { continue }
					data, err := os.ReadFile(path); if err != nil { continue }
					for _, h := range fw.e.Scan(data, fw.e.IsBin(path)) {
						fw.a.Fire(h.Lvl, "FileWatcher", h.Cat+" détecté", path, "Match: "+trunc(h.Sample, 80))
					}
				}
			}
		}
	}()
}

// ═══════════════════ COMMANDES INTERACTIVES ═══════════════════

func cmdProcesses() {
	fmt.Printf("\n  %s👁️  PROCESSUS ACTIFS%s\n", BLD, RST)
	fmt.Printf("  %s──────────────────────────────────────────────────────────%s\n", DIM, RST)
	out := runCmd("tasklist", "/v", "/fo", "csv")
	legit := map[string]bool{"system":true,"smss.exe":true,"csrss.exe":true,"wininit.exe":true,"services.exe":true,"lsass.exe":true,"svchost.exe":true,"explorer.exe":true,"dwm.exe":true,"taskhostw.exe":true,"sihost.exe":true,"ctfmon.exe":true,"runtimebroker.exe":true,"conhost.exe":true,"sentinel.exe":true,"tasklist.exe":true,"msmpeng.exe":true}
	fakeNames := map[string]string{"systeminterrupts.exe":"FAUX system!","svch0st.exe":"Imite svchost!","scvhost.exe":"Imite svchost!","svchosts.exe":"Imite svchost!","csrs.exe":"Imite csrss!","lssas.exe":"Imite lsass!"}
	susNames := []string{"stealer","grabber","keylog","hvnc","backdoor","miner","xmrig","inject","trojan"}
	runtimes := []string{"python","pythonw","node","wscript","cscript","mshta","powershell"}
	type procLine struct{ name, pid, risk, color string }
	var items []procLine
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ",", 3)
		if len(parts) < 2 { continue }
		name := strings.Trim(parts[0], `"`); pid := strings.Trim(parts[1], `"`)
		if name == "Image Name" || name == "" { continue }
		nameLow := strings.ToLower(name); risk := ""; color := GRY
		if desc, ok := fakeNames[nameLow]; ok { risk = "🚨 " + desc; color = RDB }
		if risk == "" { for _, s := range susNames { if strings.Contains(nameLow, s) { risk = "🚨 Nom suspect!"; color = RED; break } } }
		if risk == "" { for _, rt := range runtimes { if strings.Contains(nameLow, rt) { risk = "🔍 Runtime"; color = YEL; break } } }
		if risk == "" && !legit[nameLow] { color = DIM }
		items = append(items, procLine{name, pid, risk, color})
	}
	sort.Slice(items, func(i, j int) bool {
		iw, jw := 0, 0
		if strings.Contains(items[i].risk, "🚨") { iw = 2 } else if strings.Contains(items[i].risk, "🔍") { iw = 1 }
		if strings.Contains(items[j].risk, "🚨") { jw = 2 } else if strings.Contains(items[j].risk, "🔍") { jw = 1 }
		return iw > jw
	})
	highlighted := 0
	for _, it := range items { if it.risk != "" { highlighted++; fmt.Printf("    %s%6s  %-35s  %s%s\n", it.color, it.pid, it.name, it.risk, RST) } }
	if highlighted == 0 { fmt.Printf("    %s✅ Aucun processus suspect%s\n", GRN, RST) }
	fmt.Printf("\n  %s%d total, %d à surveiller%s\n\n", DIM, len(items), highlighted, RST)
}

func cmdNetwork() {
	fmt.Printf("\n  %s🌐 Connexions réseau:%s\n", BLD, RST)
	fmt.Printf("  %s──────────────────────────────────────────────────────────%s\n", DIM, RST)
	pids := pidMap(); out := runCmd("netstat", "-ano")
	suspPorts := map[string]bool{"4444":true,"5555":true,"6666":true,"1337":true,"31337":true}
	fakeProcs := map[string]bool{"systeminterrupts.exe":true,"svch0st.exe":true,"scvhost.exe":true}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "ESTABLISHED") { continue }; count++
		fields := strings.Fields(line); if len(fields) < 5 { continue }
		local, remote, pid := fields[1], fields[2], fields[4]
		name := pids[pid]; if name == "" { name = "?" }; nameLow := strings.ToLower(name)
		if strings.HasPrefix(remote, "127.") || strings.HasPrefix(remote, "[::1]") { continue }
		color, mark := DIM, " "
		if fakeProcs[nameLow] { color = RDB; mark = "🚨" }
		if mark == " " { if idx := strings.LastIndex(remote, ":"); idx > 0 { if suspPorts[remote[idx+1:]] { color = RED; mark = "⚠️ " } } }
		fmt.Printf("    %s%s %-20s %-25s → %-25s%s\n", color, mark, name, local, remote, RST)
	}
	fmt.Printf("\n  %s%d connexions%s\n", DIM, count, RST)
}

func cmdTop() {
	fmt.Printf("\n  %s📊 TOP CONNEXIONS PAR PROCESSUS%s\n", BLD, RST)
	pids := pidMap(); out := runCmd("netstat", "-ano")
	type ci struct { count int; remotes map[string]bool }
	byProc := make(map[string]*ci)
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "ESTABLISHED") { continue }
		fields := strings.Fields(line); if len(fields) < 5 { continue }
		name := pids[fields[4]]; if name == "" { name = "PID:" + fields[4] }
		key := name + " (" + fields[4] + ")"
		if _, ok := byProc[key]; !ok { byProc[key] = &ci{remotes: make(map[string]bool)} }
		byProc[key].count++
		if idx := strings.LastIndex(fields[2], ":"); idx > 0 { byProc[key].remotes[fields[2][:idx]] = true }
	}
	type entry struct { name string; count, ips int }
	var entries []entry
	for k, v := range byProc { entries = append(entries, entry{k, v.count, len(v.remotes)}) }
	sort.Slice(entries, func(i, j int) bool { return entries[i].count > entries[j].count })
	for _, e := range entries {
		bar := strings.Repeat("█", e.count); if len(bar) > 30 { bar = bar[:30] + "+" }
		color := DIM; if e.count > 10 { color = YEL }; if e.count > 30 { color = RED }
		fmt.Printf("    %s%-35s %3d conn  %2d IPs  %s%s\n", color, e.name, e.count, e.ips, bar, RST)
	}
	fmt.Println()
}

func cmdServices() {
	fmt.Printf("\n  %s🔧 SERVICES NON-MICROSOFT%s\n", BLD, RST)
	out := runCmd("wmic", "service", "where", "State='Running'", "get", "Name,DisplayName", "/format:csv")
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, ",") || strings.HasPrefix(line, "Node") { continue }
		low := strings.ToLower(line)
		if strings.Contains(low, "microsoft") || strings.Contains(low, "windows") { continue }
		parts := strings.SplitN(line, ",", 4); if len(parts) < 3 { continue }
		count++; fmt.Printf("    %-30s  %s\n", parts[2], parts[1])
	}
	fmt.Printf("\n  %s%d services non-Microsoft actifs%s\n", DIM, count, RST)
}

func cmdDNS() {
	fmt.Printf("\n  %s🌐 CACHE DNS%s\n", BLD, RST)
	fmt.Printf("  %s──────────────────────────────────────────────────────────%s\n", DIM, RST)
	out := runCmd("ipconfig", "/displaydns")
	suspTLDs := []string{".ru",".cn",".tk",".ml",".ga",".cf",".gq",".top",".pw",".cc"}
	seen := map[string]bool{}; count, flagged := 0, 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "Record Name") && !strings.Contains(line, "Nom d'enregistrement") { continue }
		parts := strings.SplitN(line, ":", 2); if len(parts) < 2 { continue }
		domain := strings.TrimSpace(parts[1])
		if domain == "" || strings.Contains(domain, "in-addr.arpa") || strings.HasSuffix(domain, ".local") { continue }
		if seen[domain] { continue }; seen[domain] = true; count++
		color := DIM; mark := ""
		for _, tld := range suspTLDs {
			if strings.HasSuffix(strings.ToLower(domain), tld) { color = YEL; mark = " 🔶 TLD suspect (" + tld + ")"; flagged++; break }
		}
		fmt.Printf("    %s%-50s%s%s\n", color, domain, mark, RST)
	}
	fmt.Printf("\n  %s%d domaines, %d suspects%s\n\n", DIM, count, flagged, RST)
}

func cmdDrivers() {
	fmt.Printf("\n  %s🔌 PILOTES NON-MICROSOFT%s\n", BLD, RST)
	fmt.Printf("  %s──────────────────────────────────────────────────────────%s\n", DIM, RST)
	out := runCmd("driverquery", "/v", "/fo", "csv")
	total, shown := 0, 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, ",") || strings.HasPrefix(line, `"Module`) { continue }; total++
		low := strings.ToLower(line)
		if strings.Contains(low, "microsoft") || strings.Contains(low, "windows") { continue }
		parts := strings.Split(line, `","`)
		if len(parts) < 4 { continue }
		name := strings.Trim(parts[0], `"`); displayName := strings.Trim(parts[1], `"`); drvType := strings.Trim(parts[3], `"`)
		if shown < 30 { shown++; fmt.Printf("    %-25s  %-35s  %s\n", name, trunc(displayName, 35), drvType) }
	}
	fmt.Printf("\n  %s%d total, %d non-Microsoft affichés%s\n\n", DIM, total, shown, RST)
}

func cmdScan(path string, engine *Engine) {
	path = strings.Trim(path, `"' `); if !exists(path) { fmt.Printf("  %sIntrouvable%s\n", RED, RST); return }
	info, _ := os.Stat(path)
	if info.IsDir() {
		fmt.Printf("\n  %s📂 Scan de: %s%s\n", BLD, path, RST)
		count, found := 0, 0
		filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil { return filepath.SkipDir }
			if d.IsDir() { if skipDirNames[strings.ToLower(d.Name())] { return filepath.SkipDir }; return nil }
			if !engine.ShouldScan(p) { return nil }
			fi, _ := d.Info(); if fi == nil || fi.Size() == 0 || fi.Size() > int64(maxFileScan) { return nil }
			count++; data, err := os.ReadFile(p); if err != nil { return nil }
			if mal := engine.CheckName(p); mal != "" { fmt.Printf("    🚨 %s — Malware: %s\n", filepath.Base(p), mal); found++ }
			for _, h := range engine.Scan(data, engine.IsBin(p)) {
				fmt.Printf("    %s %s — %s: %s\n", lvlIcon[h.Lvl], filepath.Base(p), h.Cat, trunc(h.Sample, 60)); found++
			}
			if engine.IsBin(p) {
				pe := analyzePE(data)
				if pe.IsPacked { fmt.Printf("    📦 %s — Packer: %s\n", filepath.Base(p), pe.PackerName) }
				for _, a := range pe.Anomalies { fmt.Printf("    🔍 %s — %s\n", filepath.Base(p), a) }
			}
			return nil
		})
		fmt.Printf("\n  %s%d scannés, %d détections%s\n", DIM, count, found, RST)
	} else { cmdInfo(path, engine) }
}

func cmdInfo(path string, engine *Engine) {
	path = strings.Trim(path, `"' `); if !exists(path) { fmt.Printf("  %sIntrouvable%s\n", RED, RST); return }
	info, _ := os.Stat(path)
	if info.IsDir() { fmt.Printf("\n  %s📁 %s — %d fichiers%s\n", BLD, path, countFiles(path), RST); return }
	fmt.Printf("\n  %s📄 Info:%s\n", BLD, RST)
	fmt.Printf("    Nom:      %s\n    Chemin:   %s\n    Taille:   %.1f KB\n    Modifié:  %s\n",
		filepath.Base(path), path, float64(info.Size())/1024, info.ModTime().Format("02/01/2006 15:04:05"))
	fmt.Printf("    MD5:      %s\n    SHA256:   %s\n", md5sum(path), sha256sum(path))
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		e := entropy(data); c, n := GRN, "Normal"
		if e > 6.5 { c, n = YEL, "Compressé?" }; if e > 7.2 { c, n = RED, "Chiffré/packé!" }
		fmt.Printf("    Entropie: %s%.2f/8.0 %s%s\n", c, e, n, RST)
		if isDevProject(path, data) { fmt.Printf("    Contexte: %s🔧 Projet dev%s\n", BLU, RST) }
		pe := analyzePE(data)
		if pe.IsPE {
			arch := "x86"; if pe.Is64 { arch = "x64" }
			fmt.Printf("\n    %sPE Analysis:%s Architecture: %s\n", BLD, RST, arch)
			if pe.IsPacked { fmt.Printf("      %sPacker: %s%s\n", YEL, pe.PackerName, RST) }
			for _, sec := range pe.Sections {
				col := DIM; if sec.Entropy > 7.0 { col = RED }
				fmt.Printf("      %s%-8s E:%.1f V:%d R:%d%s\n", col, sec.Name, sec.Entropy, sec.VirtSize, sec.RawSize, RST)
			}
			if len(pe.Imports) > 0 { fmt.Printf("      %sImports suspects: %s%s\n", YEL, strings.Join(pe.Imports, ", "), RST) }
			for _, a := range pe.Anomalies { fmt.Printf("      %s⚠️  %s%s\n", RED, a, RST) }
		}
		hits := engine.Scan(data, engine.IsBin(path))
		if len(hits) > 0 {
			fmt.Printf("    %s⚠️  Détections:%s\n", RED, RST)
			for _, h := range hits { fmt.Printf("       %s %s: %s\n", lvlIcon[h.Lvl], h.Cat, trunc(h.Sample, 60)) }
		} else { fmt.Printf("    %s✅ Clean%s\n", GRN, RST) }
	}
	fmt.Println()
}

func cmdKill(pidStr string) {
	pid, err := strconv.Atoi(strings.TrimSpace(pidStr))
	if err != nil { fmt.Printf("  %sPID invalide%s\n", RED, RST); return }
	name := "?"
	for _, p := range listProcs() { if int(p.PID) == pid { name = peName(&p); break } }
	fmt.Printf("  ❓ Terminer %s%s (PID %d)%s ? [y/N] ", RED, name, pid, RST)
	reader := bufio.NewReader(os.Stdin); input, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(input)) != "y" { fmt.Printf("  %sAnnulé%s\n", DIM, RST); return }
	out := runCmd("taskkill", "/F", "/PID", fmt.Sprintf("%d", pid))
	if strings.Contains(strings.ToLower(out), "success") || strings.Contains(out, "réussite") {
		fmt.Printf("  %s✅ Terminé%s\n", GRN, RST)
	} else { fmt.Printf("  %s❌ %s%s\n", RED, strings.TrimSpace(out), RST) }
}

func cmdInvestigate(pidStr string) {
	pid := strings.TrimSpace(pidStr)
	fmt.Printf("\n  %s🔍 INVESTIGATION — PID %s%s\n", BLD, pid, RST)
	fmt.Printf("  %s──────────────────────────────────────────────────────────%s\n", DIM, RST)
	out := runCmd("wmic", "process", "where", "ProcessId="+pid, "get", "Name,ExecutablePath,CommandLine,ParentProcessId", "/format:list")
	info := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, "="); idx > 0 { k, v := strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]); if v != "" { info[k] = v } }
	}
	if len(info) == 0 { fmt.Printf("  %s❌ Non trouvé%s\n", RED, RST); return }
	fmt.Printf("    Nom:     %s%s%s\n    PID:     %s\n    Parent:  %s\n    Chemin:  %s\n    Cmd:     %s\n",
		BLD, info["Name"], RST, pid, info["ParentProcessId"], info["ExecutablePath"], trunc(info["CommandLine"], 200))
	if exePath := info["ExecutablePath"]; exePath != "" && exists(exePath) {
		fi, _ := os.Stat(exePath)
		fmt.Printf("    Taille:  %.1f KB\n    MD5:     %s\n    SHA256:  %s\n", float64(fi.Size())/1024, md5sum(exePath), sha256sum(exePath))
		data, err := os.ReadFile(exePath)
		if err == nil {
			e := entropy(data); c, n := GRN, "Normal"
			if e > 6.5 { c, n = YEL, "Packé?" }; if e > 7.2 { c, n = RED, "Chiffré!" }
			fmt.Printf("    Entropie:%s%.2f %s%s\n", c, e, n, RST)
			pe := analyzePE(data)
			if pe.IsPacked { fmt.Printf("    %s📦 Packer: %s%s\n", YEL, pe.PackerName, RST) }
			if len(pe.Imports) > 0 { fmt.Printf("    %sImports: %s%s\n", YEL, strings.Join(pe.Imports, ", "), RST) }
		}
		sigOut := runCmd("powershell", "-NoProfile", "-Command", fmt.Sprintf(`(Get-AuthenticodeSignature '%s').Status`, exePath))
		sig := strings.TrimSpace(sigOut)
		if strings.Contains(sig, "Valid") { fmt.Printf("    Signature: %s✅ Valide%s\n", GRN, RST) } else { fmt.Printf("    Signature: %s⚠️  %s%s\n", RED, sig, RST) }
		exeLow := strings.ToLower(exePath)
		if strings.Contains(exeLow, `\temp\`) { fmt.Printf("    %s🚨 Exécutable dans TEMP!%s\n", RDB, RST) }
		if !strings.Contains(exeLow, `\program files`) && !strings.Contains(exeLow, `\windows\`) { fmt.Printf("    %s⚠️  Chemin inhabituel%s\n", YEL, RST) }
	}
	// Network
	fmt.Printf("\n    %sConnexions:%s\n", BLD, RST); netOut := runCmd("netstat", "-ano"); connCount := 0
	for _, line := range strings.Split(netOut, "\n") {
		if strings.Contains(line, "ESTABLISHED") { fields := strings.Fields(line)
			if len(fields) >= 5 && fields[4] == pid {
				connCount++; remote := fields[2]
				if idx := strings.LastIndex(remote, ":"); idx > 0 {
					ip := strings.Trim(remote[:idx], "[]")
					if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
						fmt.Printf("      %s → %s (%s)\n", fields[1], remote, names[0]); continue
					}
				}
				fmt.Printf("      %s → %s\n", fields[1], remote)
			}
		}
	}
	if connCount == 0 { fmt.Printf("      %sAucune%s\n", DIM, RST) }
	fmt.Println()
}

func cmdFix(alerts *AlertSystem) {
	fmt.Printf(`
  %s🔧 RÉPARATION:%s
    1. Discord desktop_core
    2. Nettoyer Temp
    3. Vider cache DNS
    4. Réparer hosts
    5. Retour
  Choix: `, BLD, RST)
	reader := bufio.NewReader(os.Stdin); input, _ := reader.ReadString('\n')
	switch strings.TrimSpace(input) {
	case "1":
		fixed := 0
		for _, v := range []string{"Discord","discordcanary","discordptb"} {
			for _, b := range []string{env("APPDATA"), env("LOCALAPPDATA")} {
				dir := filepath.Join(b, v); if !exists(dir) { continue }
				filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
					if err != nil || d == nil || d.IsDir() || d.Name() != "index.js" { return nil }
					if !strings.Contains(strings.ToLower(p), "discord_desktop_core") { return nil }
					data, _ := os.ReadFile(p); content := strings.TrimSpace(string(data))
					if len(content) > 200 || !strings.Contains(content, "require('./core.asar')") {
						os.WriteFile(p+".infected.bak", data, 0o644)
						os.WriteFile(p, []byte(`module.exports = require('./core.asar');`), 0o644)
						fmt.Printf("    %s✅ Réparé: %s%s\n", GRN, p, RST); fixed++
					}; return nil
				})
			}
		}
		if fixed == 0 { fmt.Printf("    %s✅ Aucune injection%s\n", GRN, RST) }
	case "2":
		temp := env("TEMP"); bf := []string{"login data","cookies","web data","local state","credit cards"}; removed := 0
		entries, _ := os.ReadDir(temp)
		for _, e := range entries { low := strings.ToLower(e.Name())
			for _, b := range bf { if strings.Contains(low, b) { os.Remove(filepath.Join(temp, e.Name())); fmt.Printf("    %s🗑️  %s%s\n", RED, e.Name(), RST); removed++; break } }
		}
		if removed == 0 { fmt.Printf("    %s✅ Clean%s\n", GRN, RST) }
	case "3":
		runCmd("ipconfig", "/flushdns"); fmt.Printf("  %s✅ Cache DNS vidé%s\n", GRN, RST)
	case "4":
		hostsPath := `C:\Windows\System32\drivers\etc\hosts`
		data, err := os.ReadFile(hostsPath); if err != nil { fmt.Printf("  %s❌ Impossible de lire%s\n", RED, RST); return }
		os.WriteFile(hostsPath+".sentinel.bak", data, 0o644)
		danger := []string{"malwarebytes.com","kaspersky.com","norton.com","avast.com","bitdefender.com","virustotal.com"}
		var cleaned []string; removed := 0
		for _, line := range strings.Split(string(data), "\n") {
			keep := true; low := strings.ToLower(line)
			for _, d := range danger { if strings.Contains(low, d) { keep = false; removed++; break } }
			if keep { cleaned = append(cleaned, line) }
		}
		if removed > 0 { os.WriteFile(hostsPath, []byte(strings.Join(cleaned, "\n")), 0o644)
			fmt.Printf("    %s✅ %d entrées supprimées%s\n", GRN, removed, RST)
		} else { fmt.Printf("    %s✅ Clean%s\n", GRN, RST) }
	}
}

func cmdExport(alerts *AlertSystem, cache *ScanCache) {
	dir := filepath.Join(env("USERPROFILE"), ".sentinel")
	ts := time.Now().Format("2006-01-02_15-04-05")
	jsonPath := filepath.Join(dir, "report_"+ts+".json")
	type Report struct {
		Timestamp string `json:"timestamp"`; Computer string `json:"computer"`; User string `json:"user"`
		Alerts []Alert `json:"alerts"`; Timeline []TimelineEvent `json:"timeline"`; CacheSize int `json:"cache_size"`
	}
	report := Report{time.Now().Format(time.RFC3339), env("COMPUTERNAME"), env("USERNAME"), alerts.All(), alerts.Timeline(), cache.Count()}
	data, _ := json.MarshalIndent(report, "", "  "); os.WriteFile(jsonPath, data, 0o644)

	// HTML
	htmlPath := filepath.Join(dir, "report_"+ts+".html")
	html := fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>SENTINEL Report</title>
<style>body{font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:20px}h1{color:#00ff88}
.alert{padding:8px;margin:4px 0;border-left:3px solid}.crit{border-color:red;background:#1a0000}
.high{border-color:orange;background:#1a0f00}.med{border-color:yellow;background:#1a1a00}</style></head>
<body><h1>🛡️ SENTINEL v%s Report</h1><p>%s | %s | %s</p><h2>%d alertes</h2>`,
		VERSION, time.Now().Format("02/01/2006 15:04"), env("COMPUTERNAME"), env("USERNAME"), len(report.Alerts))
	for _, a := range report.Alerts {
		cls := "med"; if a.Level >= LVL_CRIT { cls = "crit" } else if a.Level >= LVL_HIGH { cls = "high" }
		html += fmt.Sprintf(`<div class="alert %s"><b>[%s] %s:</b> %s`, cls, lvlName[a.Level], a.Module, a.Message)
		if a.Path != "" { html += " — " + a.Path }
		html += "</div>\n"
	}
	html += "</body></html>"
	os.WriteFile(htmlPath, []byte(html), 0o644)
	fmt.Printf("  %s✅ Rapports exportés:%s\n  %s   JSON: %s\n   HTML: %s%s\n", GRN, RST, DIM, jsonPath, htmlPath, RST)
}

func cmdQuarantine(quar *Quarantine, arg string) {
	if arg == "list" || arg == "" {
		items := quar.List()
		if len(items) == 0 { fmt.Printf("\n  %s✅ Quarantaine vide%s\n\n", GRN, RST); return }
		fmt.Printf("\n  %s🔒 QUARANTAINE (%d)%s\n", BLD, len(items), RST)
		for i, item := range items {
			fmt.Printf("    %s[%d]%s %s — %s — %.1f KB\n", CYN, i, RST, filepath.Base(item.Original), item.Reason, float64(item.Size)/1024)
		}
		fmt.Println()
	} else if strings.HasPrefix(arg, "restore ") {
		idx, err := strconv.Atoi(strings.TrimPrefix(arg, "restore "))
		if err != nil { fmt.Printf("  %sIndex invalide%s\n", RED, RST); return }
		if err := quar.Restore(idx); err != nil { fmt.Printf("  %s❌ %s%s\n", RED, err, RST) } else { fmt.Printf("  %s✅ Restauré%s\n", GRN, RST) }
	} else {
		path := strings.Trim(arg, `"' `)
		if err := quar.Add(path, "Manuel"); err != nil { fmt.Printf("  %s❌ %s%s\n", RED, err, RST) } else { fmt.Printf("  %s✅ Quarantaine: %s%s\n", GRN, filepath.Base(path), RST) }
	}
}

func cmdTimeline(alerts *AlertSystem) {
	events := alerts.Timeline()
	if len(events) == 0 { fmt.Printf("\n  %s✅ Aucun événement%s\n\n", GRN, RST); return }
	fmt.Printf("\n  %s📅 TIMELINE FORENSIQUE%s\n", BLD, RST)
	fmt.Printf("  %s──────────────────────────────────────────────────────────%s\n", DIM, RST)
	start := 0; if len(events) > 50 { start = len(events) - 50 }
	lastDate := ""
	for _, ev := range events[start:] {
		date := ev.Time.Format("02/01/2006")
		if date != lastDate { fmt.Printf("\n  %s─── %s ───%s\n", DIM, date, RST); lastDate = date }
		color := DIM
		switch ev.Type { case "CRITICAL": color = RDB; case "HIGH": color = RED; case "MEDIUM": color = YEL; case "LOW": color = CYN }
		fmt.Printf("    %s%s %s%s\n", color, ev.Time.Format("15:04:05"), ev.Detail, RST)
	}
	fmt.Println()
}

func cmdForensic(engine *Engine, alerts *AlertSystem, cache *ScanCache, quar *Quarantine) {
	fmt.Printf("\n  %s🔬 ANALYSE FORENSIQUE COMPLÈTE%s\n", RDB, RST)
	fmt.Printf("  %s══════════════════════════════════════════════════════════%s\n", DIM, RST)
	start := time.Now()

	fmt.Printf("  %s[1/5]%s Blitz scan...\n", CYN, RST)
	blitzScan(engine, alerts, cache, quar)

	fmt.Printf("  %s[2/5]%s Fichiers récents (<24h)...\n", CYN, RST)
	recentFiles, suspRecent := 0, 0; cutoff := time.Now().Add(-24 * time.Hour)
	for _, dir := range []string{env("TEMP"), filepath.Join(env("USERPROFILE"), "Downloads"), filepath.Join(env("USERPROFILE"), "Desktop")} {
		if !exists(dir) { continue }
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil { return filepath.SkipDir }
			if d.IsDir() { if skipDirNames[strings.ToLower(d.Name())] { return filepath.SkipDir }; return nil }
			info, err := d.Info(); if err != nil || !info.ModTime().After(cutoff) { return nil }; recentFiles++
			if engine.ShouldScan(p) { data, _ := os.ReadFile(p); if len(engine.Scan(data, engine.IsBin(p))) > 0 { suspRecent++ } }
			return nil
		})
	}
	fmt.Printf("    %s%d récents, %d suspects%s\n", DIM, recentFiles, suspRecent, RST)

	fmt.Printf("  %s[3/5]%s Historique USB...\n", CYN, RST)
	usbOut := runCmd("reg", "query", `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`); usbCount := 0
	for _, line := range strings.Split(usbOut, "\n") { if strings.Contains(line, "USBSTOR\\") { usbCount++ } }
	fmt.Printf("    %s%d périphériques%s\n", DIM, usbCount, RST)

	fmt.Printf("  %s[4/5]%s Connexions récentes...\n", CYN, RST)
	loginOut := runCmdTimeout(10*time.Second, "powershell", "-NoProfile", "-Command",
		`Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625} -MaxEvents 10 2>$null | Measure-Object | Select Count | Format-List`)
	loginCount := 0; for _, l := range strings.Split(loginOut, "\n") {
		if strings.Contains(l, "Count") { parts := strings.SplitN(l, ":", 2); if len(parts) > 1 { fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &loginCount) } }
	}
	fmt.Printf("    %s%d événements%s\n", DIM, loginCount, RST)

	fmt.Printf("  %s[5/5]%s Résumé...\n", CYN, RST)
	elapsed := time.Since(start)
	fmt.Printf(`
  %s╔══════════════════════════════════════════════════════════╗%s
  ║              🔬 RÉSULTAT FORENSIQUE                      ║
  ╠══════════════════════════════════════════════════════════╣
  ║   Fichiers récents:    %-6d (%-3d suspects)              ║
  ║   Périphériques USB:   %-6d                              ║
  ║   Connexions récentes: %-6d                              ║
  ║   Alertes totales:     %-6d                              ║
  ║   Durée:               %-6.1fs                             ║
  %s╚══════════════════════════════════════════════════════════╝%s
`, BLD, RST, recentFiles, suspRecent, usbCount, loginCount, alerts.Total(), elapsed.Seconds(), BLD, RST)
}

// ═══════════════════ INSTALL ═══════════════════

func installStartup() {
	exe, _ := os.Executable(); exe, _ = filepath.Abs(exe)
	runCmd("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "SentinelAV", "/t", "REG_SZ", "/d", fmt.Sprintf(`"%s"`, exe), "/f")
	fmt.Printf("  %s✅ Ajouté au démarrage%s\n", GRN, RST)
}
func uninstallStartup() {
	runCmd("reg", "delete", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "SentinelAV", "/f")
	fmt.Printf("  %s✅ Retiré%s\n", GRN, RST)
}

// ═══════════════════ MAIN ═══════════════════

func main() {
	enableAnsi()
	exe, _ := os.Executable(); exe, _ = filepath.Abs(exe); selfPath = strings.ToLower(exe)

	if len(os.Args) > 1 {
		switch strings.ToLower(os.Args[1]) {
		case "--install": installStartup(); return
		case "--uninstall": uninstallStartup(); return
		}
	}

	fmt.Printf(`%s
  ╔═══════════════════════════════════════════════════════════╗
  ║   ███████╗███████╗███╗  ██╗████████╗██╗███╗  ██╗        ║
  ║   ██╔════╝██╔════╝████╗ ██║╚══██╔══╝██║████╗ ██║        ║
  ║   ███████╗█████╗  ██╔██╗██║   ██║   ██║██╔██╗██║        ║
  ║   ╚════██║██╔══╝  ██║╚████║   ██║   ██║██║╚████║        ║
  ║   ███████║███████╗██║ ╚███║   ██║   ██║██║ ╚███║        ║
  ║   ╚══════╝╚══════╝╚═╝  ╚══╝   ╚═╝   ╚═╝╚═╝  ╚══╝        ║
  ║   🛡️  SENTINEL v%s — Big Brother Edition               ║
  ╚═══════════════════════════════════════════════════════════╝%s
`, CYN, VERSION, RST)

	fmt.Printf("\n  %s🖥️  %s | 👤 %s | 📅 %s%s\n", BLD, envOr("COMPUTERNAME", "?"), envOr("USERNAME", "?"),
		time.Now().Format("02/01/2006 15:04"), RST)

	sentinelDir := filepath.Join(env("USERPROFILE"), ".sentinel")
	os.MkdirAll(sentinelDir, 0o755)
	quarDir := filepath.Join(sentinelDir, "quarantine"); os.MkdirAll(quarDir, 0o755)
	logPath := filepath.Join(sentinelDir, "sentinel.log")
	cachePath := filepath.Join(sentinelDir, "scancache.json")

	alerts := NewAlerts(logPath); engine := NewEngine(); cache := NewCache(cachePath)
	quar := NewQuarantine(quarDir)
	fmt.Printf("  %s📁 %s | 💾 Cache: %d fichiers%s\n\n", DIM, sentinelDir, cache.Count(), RST)

	startTime := time.Now()

	// ═══ GUARDS (10 actifs) ═══
	type guardInfo struct{ name, desc string; fn func() }
	guards := []guardInfo{
		{"ProcessGuard", "Processus (5s)", func() { NewProcGuard(alerts).Start() }},
		{"DiscordGuard", "Discord (30s)", func() { NewDiscordGuard(alerts).Start() }},
		{"StartupGuard", "Démarrage (2min)", func() { NewStartupGuard(alerts).Start() }},
		{"TempGuard", "Temp (8s)", func() { NewTempGuard(alerts).Start() }},
		{"ClipboardGuard", "Clipper crypto (2s)", func() { NewClipGuard(alerts).Start() }},
		{"HostsGuard", "DNS hijack (30s)", func() { NewHostsGuard(alerts).Start() }},
		{"FileWatcher", "Fichiers récents (10s)", func() {
			NewFileWatcher(engine, alerts, []string{env("TEMP"),
				filepath.Join(env("USERPROFILE"), "Downloads"),
				filepath.Join(env("USERPROFILE"), "Desktop"),
				filepath.Join(env("USERPROFILE"), "Documents")}).Start()
		}},
		{"Honeypot", "Fichiers leurres (5s)", func() { NewHoneypot(alerts).Start() }},
		{"BeaconDetect", "C2 beaconing (30s)", func() { NewBeaconDetector(alerts).Start() }},
	}
	for _, g := range guards {
		g.fn(); fmt.Printf("  %s[✓]%s %-16s — %s\n", GRN, RST, g.name, g.desc)
	}

	fmt.Printf("\n  %s🛡️  SENTINEL v%s ACTIF — Big Brother is watching%s\n", BLD, VERSION, RST)
	fmt.Printf("  %s'blitz' = scan complet | 'help' = commandes%s\n", DIM, RST)
	fmt.Printf("  %s───────────────────────────────────────────────────%s\n\n", DIM, RST)

	sigCh := make(chan os.Signal, 1); signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() { <-sigCh; cache.Save(); fmt.Printf("\n  %s👋 Bye%s\n", GRN, RST); os.Exit(0) }()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("  %ssentinel>%s ", CYN, RST)
		input, err := reader.ReadString('\n'); if err != nil { break }
		input = strings.TrimSpace(input); if input == "" { continue }
		parts := strings.SplitN(input, " ", 2); cmd := strings.ToLower(parts[0])
		arg := ""; if len(parts) > 1 { arg = parts[1] }

		switch cmd {
		case "quit","exit","q": cache.Save(); fmt.Printf("  %s👋%s\n", GRN, RST); return
		case "blitz": blitzScan(engine, alerts, cache, quar)
		case "scan":
			if arg != "" { cmdScan(arg, engine) } else { fmt.Printf("  %sUsage: scan <chemin>%s\n", YEL, RST) }
		case "info":
			if arg != "" { cmdInfo(arg, engine) } else { fmt.Printf("  %sUsage: info <chemin>%s\n", YEL, RST) }
		case "investigate":
			if arg != "" { cmdInvestigate(arg) } else { fmt.Printf("  %sUsage: investigate <pid>%s\n", YEL, RST) }
		case "processes": cmdProcesses()
		case "services": cmdServices()
		case "network": cmdNetwork()
		case "top": cmdTop()
		case "dns": cmdDNS()
		case "drivers": cmdDrivers()
		case "kill":
			if arg != "" { cmdKill(arg) } else { fmt.Printf("  %sUsage: kill <pid>%s\n", YEL, RST) }
		case "fix": cmdFix(alerts)
		case "export": cmdExport(alerts, cache)
		case "quarantine": cmdQuarantine(quar, arg)
		case "timeline": cmdTimeline(alerts)
		case "forensic": cmdForensic(engine, alerts, cache, quar)
		case "alerts": n := 20; if arg != "" { fmt.Sscanf(arg, "%d", &n) }; alerts.Show(n)
		case "whitelist":
			if arg != "" {
				abs, _ := filepath.Abs(strings.Trim(arg, `"'`))
				skipPathSegments = append(skipPathSegments, `\`+filepath.Base(abs)+`\`)
				fmt.Printf("  %s✅ Whitelist: %s%s\n", GRN, abs, RST)
			} else {
				fmt.Printf("\n  %s📋 Skip paths:%s\n", BLD, RST)
				for _, s := range skipPathSegments { fmt.Printf("    • %s\n", s) }
			}
		case "cache":
			if arg == "clear" { cache.Clear(); cache.Save(); fmt.Printf("  %s✅ Cache vidé%s\n", GRN, RST) } else {
				fmt.Printf("  💾 Cache: %d fichiers | 'cache clear' pour rescan\n", cache.Count())
			}
		case "status":
			var ms runtime.MemStats; runtime.ReadMemStats(&ms); u := time.Since(startTime)
			fmt.Printf(`
  %s╔══ STATUS ══════════════════════════════════════════╗%s
  ║ 🛡️  Sentinel v%s    %sACTIF%s                           ║
  ║ ⏱️  Uptime:  %-38s ║
  ║ 💾 RAM:    %5.1f MB                                  ║
  ║ 🔔 Alertes: %-37d ║
  ║ 💿 Cache:   %-6d fichiers                           ║
  ║ 🔢 Goroutines: %-33d ║
  ║ 👁️  Guards: 9 actifs + 20 modules blitz              ║
  %s╚════════════════════════════════════════════════════╝%s
`, BLD, RST, VERSION, GRN, RST,
				fmt.Sprintf("%dh %dm %ds", int(u.Hours()), int(u.Minutes())%60, int(u.Seconds())%60),
				float64(ms.Alloc)/1024/1024, alerts.Total(), cache.Count(), runtime.NumGoroutine(), BLD, RST)

		case "help":
			fmt.Printf(`
  %s═══ COMMANDES SENTINEL v8 ══════════════════════════%s
  %s── Scan ──%s
  blitz              Scan COMPLET 20 modules (/100)
  scan <path>        Scan fichier/dossier + PE analysis
  info <path>        Hash, entropie, PE, détections
  forensic           Analyse forensique complète

  %s── Surveillance ──%s
  processes          Processus avec détection faux noms
  services           Services non-Microsoft
  network            Connexions (LOLBins, faux processus)
  top                Connexions groupées par processus
  dns                Cache DNS (domaines/TLD suspects)
  drivers            Pilotes chargés
  investigate <pid>  Analyse profonde (PE, signature, DNS)
  timeline           Chronologie forensique

  %s── Actions ──%s
  kill <pid>         Terminer un processus
  fix                Réparer Discord/Temp/DNS/Hosts
  quarantine [path]  Mettre en quarantaine
  quarantine list    Voir la quarantaine
  quarantine restore <n>  Restaurer
  whitelist <dir>    Ignorer un dossier
  export             Rapport JSON + HTML

  %s── Système ──%s
  status             RAM, uptime, alertes, goroutines
  alerts [n]         Dernières alertes
  cache [clear]      Gérer le cache de scan
  quit               Quitter
  %s════════════════════════════════════════════════════%s
`, BLD, RST, MAG, RST, MAG, RST, MAG, RST, MAG, RST, BLD, RST)

		default: fmt.Printf("  %s? '%s' inconnu — 'help'%s\n", YEL, cmd, RST)
		}
	}
}