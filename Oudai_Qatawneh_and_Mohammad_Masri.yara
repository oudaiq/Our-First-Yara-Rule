rule Unknown_Malware
{
 
meta:

	author = " Oudai Qatawneh and Mohammad Masri"
  	supervisor = "Dr Haitham Alani"
	Modified_date = "Sunday 14 May 2023, 12:12:40"
	sha1 = "75087825959CED8A90ECD317BE88FDCF159070D7"
	md5 = "288ED41EFF190F69A1BC3D156743834E"
	sha256 = "8B7207A4CDA2E4017165A89C3EDC90DE3F9128DED584E0A34CD57020751485D4"	
	filetype = " Portable Executable 32 in windows"
	KeyValue = "5"
	description = " this is basic yara rule to detect the uknown_mawlare "


strings:

	$POPUP = "No internet, No game" wide
	$PSUT = "PSUT.dll is missing!" wide
	$txtfile = "C:\\Users\\Hacked2.txt" wide
	$Cipher = "CeaserCipher" ascii
	$sql_command = "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True" wide
	$file_result = "BUFFER OVERFLOW" wide
	$link = "http://www.example.com/post_handler" wide
	$magic_byte = "MZ" 

condition:

	($magic_byte at 0 and ($sql_command or $Cipher)) or $txtfile or $link or $POPUP $PSUT
  }
