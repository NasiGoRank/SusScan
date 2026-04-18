rule APT_DeepPanda_htran_Feb15_RID3005 : APT CHINA DEMO G0009 T1020 T1090 {
   meta:
      description = "Detects a tool used by Deep Panda"
      author = "Florian Roth"
      reference = "-"
      date = "2015-02-08 12:22:01"
      score = 100
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-04-21"
      tags = "APT, CHINA, DEMO, G0009, T1020, T1090"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
      $x2 = "\\Release\\htran.pdb" ascii
      $x3 = "[SERVER]connection to %s:%d error" fullword ascii
      $x4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
      $x5 = "======================== htran V%s =======================" fullword ascii
      $x6 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
      $x7 = "[+] OK! I Closed The Two Socket." fullword ascii
      $x8 = "-listen <ConnectPort> <TransmitPort>" fullword ascii
   condition: 
      1 of them
}