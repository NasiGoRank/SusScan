rule MAL_NPM_SupplyChain_Attack_PreInstallScript_Nov25_RID3986 : DEMO MAL SCRIPT {
   meta:
      description = "Detects known malicious preinstall script in package.json"
      author = "Marius Benthin"
      reference = "https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains"
      date = "2025-11-24 19:07:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\"preinstall\": \"node setup_bun.js\"" 
   condition: 
      filesize < 10KB and all of them
}