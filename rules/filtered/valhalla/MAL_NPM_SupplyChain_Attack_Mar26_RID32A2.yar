rule MAL_NPM_SupplyChain_Attack_Mar26_RID32A2 : DEMO MAL {
   meta:
      description = "Detects package.json which include the malicious plain-crypto-js package as dependency"
      author = "Marius Benthin"
      reference = "https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan"
      date = "2026-03-31 14:13:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\"dependencies\":" 
      $s2 = { 22 70 6C 61 69 6E 2D 63 72 79 70 74 6F 2D 6A 73 22 3A [0-3] 22 [0-2] 34 2E 32 2E } 
   condition: 
      filesize < 10KB and all of them
}