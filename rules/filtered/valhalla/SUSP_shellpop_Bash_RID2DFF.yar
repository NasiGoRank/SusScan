rule SUSP_shellpop_Bash_RID2DFF : DEMO HKTL SCRIPT SUSP T1059_004 {
   meta:
      description = "Detects susupicious bash command"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18 10:55:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-04-11"
      hash1 = "36fad575a8bc459d0c2e3ad626e97d5cf4f5f8bedc56b3cc27dd2f7d88ed889b"
      id = "771b7d01-272a-5986-af07-7417b84c52ed"
      tags = "DEMO, HKTL, SCRIPT, SUSP, T1059_004"
      minimum_yara = "4.0.0"
      
   strings:
      $x1 = "bash -i >& /dev/tcp/" ascii
      $x2 = "bash -i >& /dev/tcp/" ascii base64
      $fp1 = "bash -i >& /dev/tcp/IP/PORT" ascii
   condition: 
      1 of ( $x* ) and not 1 of ( $fp* )
}