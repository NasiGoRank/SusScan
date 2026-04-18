rule APT_APT29_NOBELIUM_BoomBox_PDF_Masq_May21_1_RID3517 : APT DEMO G0016 G0118 RUSSIA {
   meta:
      description = "Detects PDF documents as used by BoomBox as described in APT29 NOBELIUM report"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
      date = "2021-05-27 15:58:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, G0016, G0118, RUSSIA"
      required_modules = "math"
      minimum_yara = "3.5.0"
      
   strings:
      $ah1 = { 25 50 44 46 2d 31 2e 33 0a 25 } 
      $af1 = { 0a 25 25 45 4f 46 0a } 
      $fp1 = "endobj" ascii
      $fp2 = "endstream" ascii
      $fp3 = { 20 6F 62 6A 0A } 
   condition: 
      filesize < 100KB and $ah1 at 0 and $af1 at ( filesize - 7 ) and math.entropy ( 16 , filesize ) > 7 and not 1 of ( $fp* )
}