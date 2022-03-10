function Invoke-Privesc {



    [CmdletBinding()]
    param(
	
		[String]
		
		$groups = ((("{4}{3}{1}{7}{0}{2}{5}{6}"-f 'henti','v','ca','ers,E','Us','ted Users{0','}','eryone,{0}Aut')) -F  [chAr]34),
	
        [Switch]
		$extended,

        [String]
		[ValidateSet("lhf",{"{1}{0}"-f 'l','ful'})]
        $mode = "lhf"
    )

	if ($extended) { $long = 'yes' } else { $long = 'no' } 

	$arguments = $groups.Split(",")


	function resolve($variable) {
        $name = &("{0}{2}{4}{1}{3}" -f 'Ge','te','t-','m','ChildI') Env:$variable
        return $name.Value
    }

    $whoami = &("{1}{0}"-f'ami','who')


    filter ConvertFrom-SDDL
    {
    

        Param (
            [Parameter( Position = 0, Mandatory = $True, ValueFromPipeline = $True )]
            [ValidateNotNullOrEmpty()]
            [String[]]
            $RawSDDL
        )

        $RawSDDL = $RawSDDL -replace "`n|`r"
        &("{0}{3}{1}{4}{2}" -f'Se','rict','e','t-St','Mod') -Version 2

        
        $RawSecurityDescriptor = [Int].Assembly.GetTypes() | &('?') { $_.FullName -eq ("{7}{14}{2}{5}{11}{0}{4}{13}{3}{10}{12}{1}{6}{8}{9}{15}" -f 'y.','l.Raw','m','n','AccessC','.Secur','Securi','Sy','tyDescr','ip','t','it','ro','o','ste','tor') }

        
        try
        {
            $Sddl = [Activator]::CreateInstance($RawSecurityDescriptor, [Object[]] @($RawSDDL))
        }
        catch [Management.Automation.MethodInvocationException]
        {
            throw $Error[0]
        }
        if ($Sddl.Group -eq $null)
        {
            $Group = $null
        }
        else
        {
            $SID = $Sddl.Group
            $Group = $SID.Translate([Security.Principal.NTAccount]).Value
        }
        if ($Sddl.Owner -eq $null)
        {
            $Owner = $null
        }
        else
        {
            $SID = $Sddl.Owner
            $Owner = $SID.Translate([Security.Principal.NTAccount]).Value
        }
        $ObjectProperties = @{
            Group = $Group
            Owner = $Owner
        }
        if ($Sddl.DiscretionaryAcl -eq $null)
        {
            $Dacl = $null
        }
        else
        {
            $DaclArray = &("{2}{1}{0}" -f'ject','Ob','New-') PSObject[](0)
            $ValueTable = @{}
            $EnumValueStrings = [Enum]::GetNames([System.Security.AccessControl.CryptoKeyRights])
            $CryptoEnumValues = $EnumValueStrings | &('%') {
                    $EnumValue = [Security.AccessControl.CryptoKeyRights] $_
                    if (-not $ValueTable.ContainsKey($EnumValue.value__))
                    {
                        $EnumValue
                    }
                    $ValueTable[$EnumValue.value__] = 1
                }
            $EnumValueStrings = [Enum]::GetNames([System.Security.AccessControl.FileSystemRights])
            $FileEnumValues = $EnumValueStrings | &('%') {
                    $EnumValue = [Security.AccessControl.FileSystemRights] $_
                    if (-not $ValueTable.ContainsKey($EnumValue.value__))
                    {
                        $EnumValue
                    }
                    $ValueTable[$EnumValue.value__] = 1
                }
            $EnumValues = $CryptoEnumValues + $FileEnumValues
            foreach ($DaclEntry in $Sddl.DiscretionaryAcl)
            {
                $SID = $DaclEntry.SecurityIdentifier
                $Account = $SID.Translate([Security.Principal.NTAccount]).Value
                $Values = &("{1}{2}{0}"-f'ct','New-Ob','je') String[](0)

                
                foreach ($Value in $EnumValues)
                {
                    if (($DaclEntry.Accessmask -band $Value) -eq $Value)
                    {
                        $Values += $Value.ToString()
                    }
                }
                $Access = "$($Values -join ',') "
                $DaclTable = @{
                    Rights = $Access
                    IdentityReference = $Account
                    IsInherited = $DaclEntry.IsInherited
                    InheritanceFlags = $DaclEntry.InheritanceFlags
                    PropagationFlags = $DaclEntry.PropagationFlags
                }
                if ($DaclEntry.AceType.ToString().Contains(("{1}{0}{2}" -f 'we','Allo','d')))
                {
                    $DaclTable[("{1}{2}{4}{0}{3}" -f 'yp','Acc','essControl','e','T')] = [Security.AccessControl.AccessControlType]::Allow
                }
                else
                {
                    $DaclTable[("{2}{1}{3}{0}" -f'rolType','essC','Acc','ont')] = [Security.AccessControl.AccessControlType]::Deny
                }
                $DaclArray += &("{2}{0}{1}" -f 'Objec','t','New-') PSObject -Property $DaclTable
            }
            $Dacl = $DaclArray
        }
        $ObjectProperties[("{0}{1}" -f 'A','ccess')] = $Dacl
        $SecurityDescriptor = &("{2}{0}{1}" -f'ew-Objec','t','N') PSObject -Property $ObjectProperties
        &("{1}{2}{0}"-f 'e-Output','Wri','t') $SecurityDescriptor
    }


    if ($mode -eq 'lhf') {

        &("{1}{0}" -f 'ite','Wr') ("{1}{12}{15}{14}{13}{9}{7}{8}{16}{3}{10}{6}{2}{5}{17}{11}{4}{0}" -f 'ed:','Date o','ploi','l','h','ts i',' ex','jus','t us',' ','ic',' patc','f last applied ','-','h ','patc','e pub','f not')
        &("{0}{1}" -f'wm','ic') qfe get InstalledOn | &("{1}{2}{0}"-f't','So','rt-Objec') { $_ -as [datetime] } | &("{1}{0}" -f 't','Selec') -Last 1


        &("{1}{0}"-f 'rite','W') ""
        &("{0}{1}" -f'Wri','te') ("{0}{1}{14}{11}{4}{13}{2}{8}{12}{10}{6}{7}{9}{5}{3}{15}" -f'----------','-','-','------','--------','------------','----','--','---','------','-','-','--','----','--','-------')
        &("{0}{1}"-f'W','rite') ""


        &("{1}{0}"-f'e','Writ') ("{0}{4}{7}{11}{6}{5}{2}{1}{3}{15}{10}{14}{13}{12}{9}{8}" -f 'Files','-',' ',' you know what',' that may cont','word','ass','ain Administra','ne:','s o',' w','tor p','i','th','ith ',' to do')
        $i = 0
        if (&("{1}{3}{2}{0}" -f'th','T','Pa','est-') $env:SystemDrive\sysprep.inf) { &("{1}{0}" -f 'e','Writ') "$env:SystemDrive\sysprep.inf" ; $i = 1}
        if (&("{0}{1}{2}" -f 'T','est','-Path') $env:SystemDrive\sysprep\sysprep.xml) { &("{0}{1}"-f'Wr','ite') "$env:SystemDrive\sysprep\sysprep.xml" ; $i = 1 }
        if (&("{1}{0}{3}{2}" -f'st-P','Te','th','a') $env:WINDIR\Panther\Unattend\Unattended.xml) { &("{0}{1}" -f'Wri','te') "$env:WINDIR\Panther\Unattend\Unattended.xml" ; $i = 1 }
        if (&("{0}{2}{1}"-f'T','-Path','est') $env:WINDIR\Panther\Unattended.xml) { &("{1}{0}" -f 'e','Writ') "$env:WINDIR\Panther\Unattended.xml" ; $i = 1 }
    	if (&("{1}{0}{2}"-f 'e','T','st-Path') $env:WINDIR\system32\sysprep\Unattend.xml) { &("{0}{1}"-f'Wr','ite') "$env:WINDIR\system32\sysprep\Unattend.xml" ; $i = 1 }
    	if (&("{0}{1}{2}" -f'T','es','t-Path') $env:WINDIR\system32\sysprep\Panther\Unattend.xml) { &("{0}{1}"-f'Wri','te') "$env:WINDIR\system32\sysprep\Panther\Unattend.xml" ; $i = 1 }
    	if (&("{1}{0}{2}"-f'es','T','t-Path') $env:WINDIR\Panther\Unattend\Unattended.xml) { &("{1}{0}" -f 'te','Wri') "$env:WINDIR\Panther\Unattend\Unattended.xml" ; $i = 1 }
    	if (&("{1}{0}{2}"-f't-','Tes','Path') $env:WINDIR\Panther\Unattend.xml) { &("{1}{0}" -f'te','Wri') "$env:WINDIR\Panther\Unattend.xml" ; $i = 1 }
    	if (&("{1}{2}{0}"-f 'th','Tes','t-Pa') $env:SystemDrive\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT) { &("{0}{1}"-f 'Wr','ite') "$env:SystemDrive\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT" ; $i = 1 }
    	if (&("{1}{2}{0}" -f'st-Path','T','e') $env:WINDIR\panther\setupinfo) { &("{1}{0}" -f 'ite','Wr') "$env:WINDIR\panther\setupinfo" ; $i = 1 }
    	if (&("{2}{1}{0}"-f't-Path','s','Te') $env:WINDIR\panther\setupinfo.bak) { &("{0}{1}" -f 'Writ','e') "$env:WINDIR\panther\setupinfo.bak" ; $i = 1 }
        if (&("{1}{2}{0}" -f 'h','Test-Pa','t') $env:SystemDrive\unattend.xml) { &("{0}{1}"-f 'Wri','te') "$env:SystemDrive\unattend.xml" ; $i = 1 }
        if (&("{3}{0}{2}{1}"-f'st','th','-Pa','Te') $env:WINDIR\system32\sysprep.inf) { &("{0}{1}"-f 'W','rite') "$env:WINDIR\system32\sysprep.inf" ; $i = 1 }
        if (&("{0}{1}{2}{3}"-f 'Tes','t','-','Path') $env:WINDIR\system32\sysprep\sysprep.xml) { &("{1}{0}"-f 'rite','W') "$env:WINDIR\system32\sysprep\sysprep.xml" ; $i = 1 }
        if (&("{1}{2}{0}" -f'h','T','est-Pat') $env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\Config\web.config) { &("{0}{1}" -f'W','rite') "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\Config\web.config" ; $i = 1 }
        if (&("{0}{1}" -f 'Te','st-Path') $env:SystemDrive\inetpub\wwwroot\web.config) { &("{1}{0}"-f 'e','Writ') "$env:SystemDrive\inetpub\wwwroot\web.config" ; $i = 1 }
        if (&("{1}{0}{2}" -f '-Pat','Test','h') ("$env:AllUsersProfile\Application "+(('Da'+'t'+'a93'+'jMcAfee'+'93j'+'Commo'+'n'+' ')-cRePlaCE  '93j',[chAR]92)+(('Fra'+'me'+'w'+'orkhv'+'oSit'+'eLi'+'st.xml')  -CRePLace  ([ChAR]104+[ChAR]118+[ChAR]111),[ChAR]92))) { &("{1}{0}" -f 'te','Wri') ("$env:AllUsersProfile\Application "+('D'+'atana'+'2'+'McAf'+'eena2'+'Common ').RePlACe(([cHAR]110+[cHAR]97+[cHAR]50),[StrINg][cHAR]92)+('Framew'+'ork'+'{0'+'}S'+'iteList.xml')-F  [ChaR]92) ; $i = 1 }
        if (&("{0}{2}{3}{1}"-f 'Te','th','s','t-Pa') HKLM:\SOFTWARE\RealVNC\WinVNC4) { &("{1}{2}{0}" -f 'm','Get-Chi','ldIte') -Path HKLM:\SOFTWARE\RealVNC\WinVNC4 ; $i = 1 }
        if (&("{1}{0}{2}" -f'Pat','Test-','h') HKCU:\Software\SimonTatham\PuTTY\Sessions) { &("{0}{4}{3}{1}{2}"-f'Get-Ch','e','m','ldIt','i') -Path HKCU:\Software\SimonTatham\PuTTY\Sessions ; $i = 1 }
        if ($i -eq 0) { &("{0}{1}" -f'Wri','te') ("{4}{0}{3}{1}{2}" -f ' n',' fo','und.','ot','Files')}


        &("{1}{0}" -f 'ite','Wr') ""
        &("{0}{1}"-f 'Wr','ite') ("{1}{5}{2}{0}{6}{8}{9}{3}{12}{4}{7}{10}{11}" -f'----','---------','--','-','-----','---','--------------------','-','-','------','-------------','-','----')
        &("{1}{0}" -f 'e','Writ') ""


        &("{0}{1}" -f 'Wri','te') ("{20}{11}{14}{9}{13}{8}{1}{6}{0}{26}{21}{5}{22}{18}{23}{15}{2}{24}{16}{17}{4}{12}{10}{25}{7}{3}{19}"-f'i','ll','M','eloadi',' m','lers ','ed - ','e to DLL Sid','ta','if S','y a','i','an','CCM is ins','ng ','h SYSTE','privilege','s,',' run','ng:','Check','l','are',' wit',' ','re vulnerabl','nsta')
        $result = $null
        $result = &("{0}{2}{1}{3}"-f 'G','Wm','et-','iObject') -Namespace ((("{4}{2}{1}{5}{0}{6}{3}"-f 'e','mfBqcl','ootfBqcc','SDK','r','i','nt')).replACe('fBq','\')) -Class CCM_Application -Property * | &("{0}{1}"-f'sel','ect') Name,SoftwareVersion
        if ($result) { $result }
        else { &("{0}{1}"-f'Writ','e') ("{3}{2}{1}{0}"-f 'd.','alle','t Inst','No') }


        &("{1}{0}" -f'rite','W') ""
        &("{1}{0}" -f'rite','W') ("{10}{11}{1}{9}{8}{5}{7}{6}{4}{2}{12}{0}{3}" -f'----','---','-','-----------------','---','-------','-','-','-','------','----','-------------','---------')
        &("{0}{1}" -f 'W','rite') ""


        &("{0}{1}"-f'W','rite') ((("{20}{23}{27}{2}{16}{26}{28}{25}{17}{3}{34}{13}{15}{18}{22}{32}{12}{10}{8}{1}{30}{7}{21}{19}{24}{4}{29}{0}{31}{14}{33}{9}{6}{11}{5}" -f 'dows/loca','0}SY','ing A','vated - inst','i','ed:','l_','EM -','Y{','tal','T','elevat','I',' ','/','as','lw','e',' N','loit','Ch',' exp','T AUT','e','/w','El','aysInstal','ck','l','n','ST','l','HOR','always_ins','all *.msi files'))  -F  [chAr]92)
        $i = 0
        if (&("{2}{0}{1}"-f'st','-Path','Te') HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer) { &("{3}{0}{2}{1}"-f 'mPrope','y','rt','Get-Ite') -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated ; $i = 1 }
        if (&("{1}{2}{0}"-f'th','Tes','t-Pa') HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer) { &("{2}{1}{4}{0}{3}"-f 'per','te','Get-I','ty','mPro') -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated ; $i = 1 }
        if ($i -eq 0) { &("{1}{0}" -f'e','Writ') ("{2}{1}{3}{0}"-f'nd.','stries ','Regi','not fou')}


        &("{0}{1}"-f 'Writ','e') ""
        &("{0}{1}"-f'Wri','te') ("{13}{15}{4}{1}{2}{0}{12}{11}{5}{8}{3}{9}{6}{14}{10}{16}{7}" -f'-','--','------','--','--','-','-------','---','----','---------','--','----------------','-','-----','------','--','-')
        &("{0}{1}"-f 'Writ','e') ""


        &("{0}{1}" -f'Wr','ite') ("{2}{6}{4}{0}{5}{1}{3}" -f' pot','to','Che',':','rotten','a','cking privileges - ')
        $result = $null
        $result = (&("{0}{1}{2}" -f 'w','hoam','i') /priv | &("{0}{2}{1}"-f'f','dstr','in') /i /C:"SeImpersonatePrivilege" /C:"SeTcbPrivilege" /C:"SeBackupPrivilege" /C:"SeRestorePrivilege" /C:"SeCreateTokenPrivilege" /C:"SeLoadDriverPrivilege" /C:"SeTakeOwnershipPrivilege" /C:"SeDebugPrivilege" 2> $null) | &("{1}{0}{2}" -f't','Out-S','ring')
        if ($result) { &("{0}{1}"-f'Writ','e') $result } else { &("{0}{1}"-f 'Writ','e') ("{5}{2}{8}{6}{4}{7}{1}{9}{0}{3}" -f'exploit','ot',' pr','.','o not allo','User','eges d','w for rotten p','ivil','ato ') }
            

        &("{1}{0}"-f 'te','Wri') ""
        &("{0}{1}" -f'Wr','ite') ("{1}{16}{4}{7}{11}{3}{20}{19}{17}{14}{12}{13}{0}{10}{9}{8}{18}{2}{15}{5}{6}" -f '--','-','--','--','------','-','---','----','-----','-----','-','---','----','-------','--','------','-------','----','--','--','-')
        &("{0}{1}" -f'W','rite') ""


        &("{0}{1}" -f 'W','rite') ("{9}{10}{0}{1}{6}{8}{7}{2}{5}{3}{4}{11}" -f'ec','kin','TTP -',' WS','U',' eg.','g','US uses H',' if WS','C','h','Xploit:')
        $i = 0
        if (&("{2}{0}{1}"-f'-Pa','th','Test') HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate) { (&("{5}{1}{4}{0}{3}{2}"-f'mPro','t-I','rty','pe','te','Ge') -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name WUServer).WUServer ; $i = 1 }
        if ($i -eq 0) { &("{1}{0}"-f'e','Writ') ("{4}{1}{6}{3}{0}{2}{5}" -f 'ration not','US misc',' foun','gu','WS','d.','onfi')}


        &("{1}{0}"-f'ite','Wr') ""
        &("{1}{0}" -f'te','Wri') ("{8}{12}{4}{5}{6}{11}{16}{10}{13}{2}{7}{17}{15}{3}{1}{14}{9}{0}" -f'-','------','---','----','-','------','-------','-','-','--','-----','---------','--','--------','-','----','---','------')
        &("{0}{1}" -f 'Wri','te') ""
        
        
        &("{1}{0}" -f 'e','Writ') ("{7}{15}{29}{12}{9}{14}{1}{27}{18}{28}{30}{5}{22}{0}{11}{6}{24}{21}{19}{23}{25}{3}{10}{2}{8}{16}{17}{26}{4}{13}{20}"-f'missions run execut','wi','rus',' - exploit/windows/l','vice_p','ave p','om ','Services ','t',' ','ocal/t','able fr','th and not','ath','enclosed ','with space','e','d_','es ','fferen',':','i','er','t direct','d','ory','ser','th quot','- if ',' in pa','you h')
        $result = $null
        $result = &("{0}{2}{1}" -f'Get-','t','WmiObjec') win32_service | &("{2}{3}{0}{1}"-f'e','ct','Where','-Obj') {($_.PathName -like '* *') -and ($_.PathName -notlike '*"*') -and ($_.PathName -notlike ((("{2}{1}{0}{3}"-f'ind','feW','*C:K','ows*'))  -crePLace ([char]75+[char]102+[char]101),[char]92))} | &("{3}{2}{1}{0}" -f'ect','-Obj','ch','ForEa') { &("{1}{0}"-f 'te','Wri') $_.PathName }
        if ($result -ne $null) { &("{1}{0}"-f'te','Wri') $result | &("{1}{0}" -f 't','Sor') -Unique } else { &("{1}{0}" -f 'e','Writ') ("{3}{2}{5}{1}{6}{4}{0}" -f 'found.','s ',' serv','Weak','ot ','ice','were n') }


        &("{0}{1}"-f 'Writ','e') ""
        &("{0}{1}"-f 'Wri','te') ("{3}{14}{11}{12}{6}{8}{0}{7}{10}{9}{1}{2}{13}{4}{5}" -f'-','------','---','------','-----','-----------------','---','---','----','----','----','-','-----','------','--')
        &("{0}{1}" -f'W','rite') ""


        &("{0}{1}" -f 'Writ','e') ("{12}{0}{13}{11}{6}{14}{10}{15}{4}{1}{9}{2}{16}{17}{7}{5}{8}{3}"-f 'TH','ace bin',' or DLL to ex','te','s - pl','r','tries p',' befo','e legitima','ary','ssio','n','PA',' variable e','ermi','n','ecu','te')
        $result = $null
        $result = $env:path.split(";") | &("{0}{1}{2}" -f'For','Ea','ch') { Trap { Continue }; (&("{1}{0}{2}"-f't-Ac','Ge','l') $_).Access; $o = $_ } | &("{1}{2}{3}{0}"-f'h-Object','Fo','rE','ac') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{4}{8}{12}{1}{32}{40}{36}{17}{41}{28}{7}{31}{21}{38}{9}{13}{34}{10}{3}{14}{29}{20}{2}{6}{23}{39}{15}{16}{0}{35}{26}{22}{27}{30}{18}{19}{11}{37}{33}{5}{24}{25}" -f 's','{0}Chan','T','l{0}','App','37','a','ories','endDa','eF','tro','5','ta','iles{','Modi','ne','r','{0}C','56{','0}-','{0}','}Crea','}','k','6{0}107','3741824','{0}Write{0','Wri','rect','fy','teData{0}2684354','{0','geP','805','0}FullCon','hip','s','36','t','eOw','ermission','reateDi')) -F[chaR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}"-f 'rite','W') ('Gr'+'oup: '+"$arg, "+'Pe'+'rmiss'+'ions'+': '+"$rights "+'on'+' '+"$o") } } }
        if ($result -ne $null) { &("{0}{1}"-f 'Writ','e') $result | &("{0}{1}" -f 'So','rt') -Unique } else { &("{1}{0}" -f 'e','Writ') ("{15}{4}{6}{14}{7}{11}{8}{12}{16}{1}{13}{3}{2}{10}{9}{0}{5}" -f'all group','le ','e','ies ar','mis','s.','sion','fo','all','t for ',' correc','r ',' PATH var','entr','s set ','Per','iab') }
    	

        &("{0}{1}"-f 'Wri','te') ""
        &("{1}{0}"-f'e','Writ') ("{9}{11}{6}{10}{5}{2}{12}{17}{3}{16}{15}{8}{13}{7}{4}{1}{14}{0}" -f'------','----','-------','--','---','----','---','----','--','------','--','---','------','-----','-','---','---','------')
        &("{0}{1}"-f'W','rite') ""
     
     
        &("{1}{0}"-f 'e','Writ') ("{6}{9}{8}{2}{5}{1}{7}{4}{3}{0}{10}"-f 'r','ckdo','tory','na','r windows bi',' permissions - ba','System3','o',' direc','2','ies:')
        $result = $null
        $result = (&("{1}{0}" -f'Acl','Get-') C:\Windows\system32).Access | &("{3}{2}{0}{1}" -f 'Each-Ob','ject','r','Fo') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{41}{18}{31}{21}{10}{23}{44}{5}{13}{40}{7}{43}{26}{8}{25}{15}{2}{12}{39}{33}{36}{6}{4}{0}{42}{17}{14}{20}{30}{11}{37}{9}{3}{27}{32}{34}{1}{19}{29}{16}{35}{38}{24}{28}{22}" -f 'ullContr','0268435456qO0-53','oriesqO0Cr','O','O0F','0ChangePermis','sq','r','eD','pq','t','rs','e','sionsqO','O0','ct','O','lqO0Modifyq','en','680','TakeOwn','Da','4','a','1','ire','at','0Writ','82','5376q','e','d','eq','teFil','O0WriteDataqO','01073','e','hi','74','a','0C','App','o','e','qO'))  -RepLACE ([ChaR]113+[ChaR]79+[ChaR]48),[ChaR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}"-f 'Wr','ite') ('Gro'+'up: '+"$arg, "+'Pe'+'rmissio'+'ns: '+"$rights "+'on'+' '+(('C:m'+'IoWi'+'n'+'d'+'owsmIosyste'+'m32') -cRePLACe  'mIo',[cHar]92)) } } }
        if ($result -ne $null) { &("{0}{1}" -f'Wri','te') $result | &("{1}{0}"-f'rt','So') -Unique } else { &("{0}{1}"-f 'Writ','e') ("{1}{7}{14}{2}{6}{3}{9}{8}{5}{0}{11}{12}{13}{10}{4}" -f 'y are','P','o','s set','roups.','director','n','ermis','32 ',' on System','rect for all g',' ','c','or','si') }
        

        &("{0}{1}"-f'Wri','te') ""
        &("{1}{0}"-f 'e','Writ') ("{9}{2}{12}{8}{6}{4}{14}{11}{1}{7}{13}{0}{10}{3}{5}"-f'------','----------','--','--','-----','--','----','-','--------','--------------','--','-----','--','-----','--')
        &("{0}{1}"-f'W','rite') ""

        
        &("{0}{1}"-f 'W','rite') ("{10}{13}{11}{8}{5}{0}{2}{7}{14}{4}{12}{6}{3}{1}{9}"-f'e',' windows b','ctories permiss','or','ac','s and dir','o','i','e','inaries:','Sys','em32 fil','kd','t','ons - b')
        $result = $null
        $result = &("{2}{1}{0}" -f 'ldItem','et-Chi','G') C:\Windows\system32 -Recurse 2> $null | &("{0}{1}{3}{2}{4}" -f 'For','Each-O','je','b','ct') { Trap { Continue }; $o = $_.FullName; (&("{1}{2}{0}"-f'Acl','G','et-') $_.FullName).Access } | &("{1}{2}{4}{0}{3}"-f'Objec','For','E','t','ach-') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{18}{14}{3}{0}{22}{17}{24}{2}{7}{16}{19}{10}{12}{13}{1}{9}{4}{5}{6}{8}{23}{11}{20}{21}{15}"-f 'C','eOwn','torie','taf2TChangePermissionsf2T','rshipf2TWri','tef2TWriteDataf2','T2','sf2TCreateF','6843545','e','ullContr','536805376f2','ol','f2TModifyf2TTak','pendDa','4','ile','ea','Ap','sf2TF','T','107374182','r','6f2T-','teDirec'))  -rEPlACE ([CHaR]102+[CHaR]50+[CHaR]84),[CHaR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}"-f 'rite','W') ('G'+'roup: '+"$arg, "+'Pe'+'r'+'missio'+'ns: '+"$rights "+'on'+' '+"$o") } } }
        if ($result -ne $null) { &("{0}{1}"-f 'Writ','e') $result | &("{0}{1}" -f 'S','ort') -Unique } else { &("{1}{0}"-f 'e','Writ') ("{1}{5}{6}{2}{9}{8}{7}{0}{11}{13}{3}{4}{10}{12}" -f ' ','Permissi','et o','l gr','ou','o','ns s','32',' System','n','p','files and directories are corre','s.','ct for al') }
        

        &("{0}{1}" -f'Wr','ite') ""
        &("{1}{0}"-f 'ite','Wr') ("{9}{4}{18}{2}{6}{17}{16}{10}{7}{1}{3}{0}{8}{12}{19}{15}{14}{11}{5}{13}{20}"-f'----------','---','------','-','-','----','--','-----------','-','-','-','----','--','-','-------','--','--','-','-','-','--------')
        &("{1}{0}" -f'e','Writ') ""


        &("{1}{0}"-f 'te','Wri') ("{10}{15}{0}{1}{3}{17}{13}{4}{5}{7}{22}{18}{11}{8}{19}{14}{12}{2}{6}{20}{9}{16}{21}"-f ' ','dire','in','c','ea','d ','g ea','p',' ','h created dire','Window','LL','ad','ry r','elo','s Temp','ctory','to',' D','Sid','c',':','ermissions -')
        $result = $null
        $result = (&("{1}{0}"-f 'Acl','Get-') C:\Windows\Temp).Access | &("{1}{3}{0}{2}"-f'j','For','ect','Each-Ob') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{4}{12}{5}{2}{6}{0}{13}{14}{11}{1}{9}{10}{7}{8}{3}"-f 'Mo','}Ta','}FullCon','y','ChangePe','ns{0','trol{0}','ership{0}ListDire','ctor','k','eOwn','y{0','rmissio','di','f'))  -F [cHAr]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}" -f 'Wri','te') ('Gr'+'oup:'+' '+"$arg, "+'Permissio'+'n'+'s: '+"$rights "+'on'+' '+('C:2DF'+'W'+'ind'+'ows'+'2D'+'Fsyste'+'m32').rEPlaCe('2DF',[StRINg][chAR]92)) } } }
        if ($result -ne $null) { &("{0}{1}" -f 'Writ','e') $result | &("{1}{0}" -f'rt','So') -Unique } else { &("{1}{0}" -f'rite','W') ("{1}{4}{3}{0}{10}{2}{8}{5}{6}{9}{12}{11}{7}" -f 'ws Te','Permis','c','s set on Windo','sion',' are co','rrect fo','ps.','tory','r a','mp dire','rou','ll g') }
            

        &("{1}{0}"-f'e','Writ') ""
        &("{1}{0}"-f 'ite','Wr') ("{5}{7}{2}{4}{3}{15}{6}{10}{9}{0}{14}{12}{13}{8}{1}{11}" -f'--------','-','--','--','--','---','---','--------','-----','-','------','---------','-','---','---------------','-')
        &("{1}{0}"-f'ite','Wr') ""


        &("{0}{1}" -f'Wri','te') ("{15}{14}{6}{1}{2}{9}{16}{5}{17}{11}{10}{7}{8}{4}{12}{13}{0}{3}" -f 'n',' ','direc','aries:','ind','ions','Files','kdoo','r w','t','ac','- b','ows b','i','m ','Progra','ory permiss',' ')
        $result = $null
        $result = (&("{1}{2}{0}" -f'l','Get-','Ac') "$env:ProgramFiles").Access | &("{0}{1}{2}" -f'Fo','rEach-Objec','t') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{30}{33}{10}{26}{32}{14}{13}{1}{25}{12}{4}{18}{39}{34}{2}{28}{24}{11}{5}{3}{0}{41}{31}{8}{16}{40}{29}{37}{6}{15}{19}{27}{21}{7}{36}{23}{17}{38}{9}{20}{22}{35}" -f '{0}Take','C','0','ol{0}Modify','s{','r','a{0}2','}','r','6','n','nt','teDirectorie','}','missions{0','68','shi','53','0}Cre','435','{0}107','{0','3','80','lCo','rea','dData{0}ChangeP','456','}Ful','}Write{0}WriteD','App','wne','er','e','iles{','741824','-536','at','7','ateF','p{0','O')) -F  [CHaR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}" -f'Wri','te') ('Grou'+'p: '+"$arg, "+'P'+'ermissi'+'ons'+': '+"$rights "+'o'+'n '+('C:6WXWi'+'nd'+'ows'+'6WXsys'+'t'+'em32').rEpLAcE(([cHAr]54+[cHAr]87+[cHAr]88),'\')) } } }
        $result += (&("{1}{0}" -f 'l','Get-Ac') ${env:ProgramFiles(x86)}).Access | &("{1}{2}{0}{3}" -f 'ec','ForEac','h-Obj','t') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{11}{10}{23}{16}{7}{13}{25}{4}{18}{0}{1}{5}{8}{9}{3}{14}{21}{27}{12}{26}{20}{6}{19}{24}{2}{15}{22}{17}{28}" -f 'irectories','Z9oCreate','9o26843','olZ9oM','reat','Fil','eDa','Permissi','esZ9oFullCon','tr','endDataZ9','App','ersh','onsZ9','odifyZ9','5456','hange','6Z9','eD','t','Writ','oT','Z9o-53680537','oC','aZ','oC','ipZ9oWriteZ9o','akeOwn','o1073741824'))  -cReplACE([cHar]90+[cHar]57+[cHar]111),[cHar]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}" -f'W','rite') ('Gro'+'u'+'p: '+"$arg, "+'Per'+'mission'+'s:'+' '+"$rights "+'o'+'n '+(('C:Z'+'2wWind'+'ow'+'sZ2wsy'+'stem32')  -CReplACE([CHaR]90+[CHaR]50+[CHaR]119),[CHaR]92)) } } }
        if ($result -ne $null) { &("{1}{0}"-f 'e','Writ') $result | &("{0}{1}" -f 'So','rt') -Unique } else { &("{0}{1}"-f'Wr','ite') ("{17}{14}{16}{3}{0}{4}{5}{11}{18}{2}{9}{13}{10}{8}{19}{15}{7}{1}{6}{12}"-f'set','al','m F',' ',' ','o','l group','for ',' corr','ile','tory are','n Progr','s.','s direc','ermiss',' ','ions','P','a','ect') }
        

        &("{0}{1}"-f 'W','rite') ""
        &("{0}{1}"-f'Wr','ite') ("{6}{4}{12}{1}{14}{16}{8}{3}{7}{13}{10}{9}{2}{0}{5}{11}{15}"-f'-------','--','--','--','--','---','-','----','-----','-------','-----','---','-','---','--','-----------------','----')
        &("{1}{0}"-f 'te','Wri') ""


        &("{0}{1}" -f'W','rite') ("{13}{5}{14}{1}{0}{11}{9}{6}{2}{8}{7}{10}{3}{4}{12}" -f'es p','and directori','ackdoor win','b','i','am F','b','w','do','missions - ','s ','er','naries:','Progr','iles files ')
        $result = $null
        $result = &("{3}{0}{1}{2}"-f'et-Ch','i','ldItem','G') "$env:ProgramFiles" -Recurse 2> $null | &("{0}{2}{3}{1}"-f 'For','ch-Object','E','a') { Trap { Continue }; $o = $_.FullName; (&("{0}{1}" -f 'Get-Ac','l') $_.FullName).Access } | &("{0}{3}{1}{2}" -f'F','ec','t','orEach-Obj') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{8}{0}{22}{14}{3}{19}{2}{13}{23}{9}{5}{10}{16}{18}{11}{15}{25}{24}{1}{6}{7}{17}{12}{21}{4}{20}" -f 'p','ipxX','is','ePe','56','ctoriesxXnCreateFilesxX','nWri','texXnWriteD','Ap','CreateDire','nFullCo','ModifyxXnTak','684','si','Chang','eOwner','ntrolx','ataxXn2','Xn','rm','xXn-536805376xXn1073741824','354','endDataxXn','onsxXn','h','s')).RePLACE('xXn',[StRing][ChaR]124)) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}"-f 'Writ','e') ('G'+'roup: '+"$arg, "+'P'+'erm'+'iss'+'ions: '+"$rights "+'on'+' '+"$o") } } }
        $result += &("{0}{2}{1}{3}"-f'Get-C','ildIt','h','em') ${env:ProgramFiles(x86)} -Recurse 2> $null | &("{3}{0}{1}{2}" -f 'ch-Obj','e','ct','ForEa') { Trap { Continue }; $o = $_.FullName; (&("{2}{1}{0}"-f '-Acl','t','Ge') $_.FullName).Access } | &("{2}{1}{0}{4}{3}" -f 'b','h-O','ForEac','ct','je') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{2}{24}{31}{1}{19}{16}{25}{5}{35}{17}{8}{4}{39}{26}{21}{18}{11}{0}{27}{38}{36}{12}{20}{15}{14}{33}{22}{23}{34}{40}{9}{37}{30}{6}{28}{29}{3}{10}{7}{13}{32}" -f'est','QCChan','AppendD','6tQC-53','te','si','8','6tQC1073','Crea','te','680537','il','ltQC','7','ytQCT','f','r','QC','eateF','gePe','Modi','CCr','wnership','tQCW','a','mis','estQ','QCFul','43','545','C26','tat','41824','akeO','ritet','onst','tro','DatatQ','lCon','Directori','QCWri')).ReplacE(([chaR]116+[chaR]81+[chaR]67),'|')) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}"-f'e','Writ') ('Gro'+'up'+': '+"$arg, "+'Per'+'mis'+'si'+'o'+'ns: '+"$rights "+'o'+'n '+"$o") } } }
        if ($result -ne $null) { &("{0}{1}"-f'W','rite') $result | &("{1}{0}"-f 'ort','S') -Unique } else { &("{0}{1}" -f 'Writ','e') ("{4}{19}{2}{1}{13}{5}{6}{20}{11}{15}{18}{17}{12}{3}{0}{16}{9}{10}{7}{14}{8}"-f'correct ','si','s','are ','Perm','s se','t',' ','ps.','or',' all','rog','es ','on','grou','ram Files','f','iles and directori',' f','i',' on P') }
        

        &("{1}{0}"-f'rite','W') ""
        &("{0}{1}"-f'W','rite') ("{18}{10}{5}{15}{6}{13}{11}{7}{16}{17}{4}{0}{14}{3}{1}{12}{2}{9}{8}" -f '------','--','--','-------','--','--------------','--','--------','--','-----','-','---','--','-','-','--','--------','-','-')
        &("{1}{0}"-f 'ite','Wr') ""


        &("{1}{0}"-f 'e','Writ') ("{15}{2}{5}{9}{3}{1}{17}{6}{18}{0}{8}{11}{14}{4}{13}{10}{12}{16}{7}" -f'with p','cute',' users startup pe','s - exe','o','rmissi','r','user:','er','on','f ','m','logge','ns o','issi','All','d ',' bina','y ')
        $result = $null
        $result = (&("{0}{2}{1}" -f'G','t-Acl','e') ("$env:ProgramData\Microsoft\Windows\Start "+(('Menu'+'kAM'+'Prog'+'ra'+'m'+'sk'+'AMStar'+'tu'+'p')  -crEpLacE([ChAR]107+[ChAR]65+[ChAR]77),[ChAR]92))).Access | &("{1}{0}{3}{2}"-f'Eac','For','Object','h-') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{21}{0}{13}{22}{24}{2}{11}{15}{8}{18}{7}{12}{5}{16}{14}{4}{10}{26}{9}{17}{23}{1}{6}{20}{3}{19}{25}"-f 'nd','0','angePer','7','ipskyWri','teFilesskyFu','5','esskyCre','skyCreate','8435456sky','te','m','a','Datask','wnersh','issions','llControlskyModifyskyTakeO','-53','Directori','3741','376sky10','Appe','y','68','Ch','824','skyWriteDatasky26')).replaCE(([ChAr]115+[ChAr]107+[ChAr]121),[StRiNg][ChAr]124)) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}" -f'rite','W') ('Gro'+'up'+': '+"$arg, "+'P'+'erm'+'iss'+'ions'+': '+"$rights "+'o'+'n '+"$env:ProgramData\Microsoft\Windows\Start "+('Men'+'u{0}Pro'+'grams'+'{0}'+'St'+'artup')-F [char]92) } } }
        $result += &("{2}{0}{1}"-f 'ildIte','m','Get-Ch') ("$env:ProgramData\Microsoft\Windows\Start "+(('M'+'e'+'n'+'uSiCPro'+'gramsS'+'iCSta'+'rtup')-REplACe  'SiC',[cHaR]92)) -Recurse | &("{0}{2}{3}{1}"-f'F','ct','orEach-Ob','je') { $o = $_.FullName; (&("{2}{1}{0}" -f 'Acl','t-','Ge') $_.FullName).Access } | &("{0}{1}{3}{2}"-f'Fo','rEach','Object','-') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{28}{31}{3}{15}{7}{10}{22}{32}{13}{6}{23}{27}{2}{34}{19}{25}{40}{45}{14}{44}{5}{38}{39}{21}{4}{12}{1}{20}{29}{17}{41}{11}{35}{16}{33}{0}{30}{8}{26}{36}{46}{24}{37}{42}{9}{43}{18}" -f 'ataKaX','odi','ct','ndDataK','a','esKaX','ionsKaXCr','ha','4','107374','n','Wr','XM','ss','i','aXC','XWr','ner','24','riesKa','fyKaXTake','olK','g','ea','3','XCre','56','teDire','App','Ow','268435','e','ePermi','iteD','o','iteKa','KaX-','6','FullCont','r','ate','shipKaX','805376KaX','18','l','F','5')).REpLAce('KaX',[string][chaR]124)) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}"-f 'te','Wri') ('Gr'+'o'+'up: '+"$arg, "+'Per'+'mi'+'ssions: '+"$rights "+'on'+' '+"$o") } } }
        if ($result -ne $null) { &("{0}{1}" -f 'W','rite') $result | &("{1}{0}"-f't','Sor') -Unique } else { &("{0}{1}"-f 'W','rite') ("{12}{13}{3}{2}{11}{5}{9}{4}{8}{0}{6}{14}{1}{10}{7}"-f' are correct ','ll ','All Users star','on ','nd directori','p file','for ','s.','es','s a','group','tu','Permission','s set ','a') }
            

        &("{0}{1}" -f'Wr','ite') ""
        &("{1}{0}" -f'te','Wri') ("{10}{4}{7}{6}{5}{0}{2}{11}{3}{1}{9}{8}" -f'------------','--','-','---','------------','---','------------------','---','--','----','-----','-----')
        &("{0}{1}"-f'Wr','ite') ""


        &("{1}{0}"-f 'e','Writ') ("{20}{12}{6}{17}{2}{5}{19}{13}{8}{7}{1}{14}{0}{10}{9}{11}{16}{15}{18}{3}{4}" -f'un at s','re a','- backdoor startup','r','s:',' binaries and check i','les permi',' a','y','up','tart',' b','xecutab','the','lso r','her u','y ot','ssions ','se','f ','Startup e')
        $result = $null
        $result = &("{1}{0}{2}{3}"-f '-ChildIt','Get','e','m') ("$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start "+(('Me'+'n'+'u3v'+'H'+'Programs'+'3vHSt'+'artup') -crePlACe  ([char]51+[char]118+[char]72),[char]92)) -Recurse | &("{0}{1}{2}"-f'ForEa','ch-Ob','ject') { $o = $_.FullName; (&("{0}{1}" -f 'Get-Ac','l') $_.FullName).Access } | &("{2}{0}{1}" -f'Each-Objec','t','For') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{22}{43}{3}{24}{12}{17}{14}{35}{42}{34}{31}{23}{18}{11}{25}{2}{45}{6}{0}{19}{36}{16}{40}{33}{26}{13}{9}{46}{7}{4}{29}{28}{8}{41}{21}{37}{30}{39}{44}{10}{47}{5}{38}{20}{1}{32}{15}{27}"-f 'eFiles{','-536805376{','0','{0}C','ake','8435','t','y{0}T','ership','l{0','{0','es','ge','o','ion','737','F','Permiss','tori','0','6{0}','i','Append','ec','han','{','Contr','41824','wn','O','}','r','0}10','ll','Di','s{0}C','}','te{0','45','Wri','u','{0}Wr','reate','Data','teData','}Crea','}Modif','}26'))-f [chAR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}"-f 'te','Wri') ('Gro'+'up'+': '+"$arg, "+'Per'+'missio'+'ns: '+"$rights "+'on'+' '+"$o") } } }
        $result += (&("{0}{1}{2}" -f'G','et-','Acl') hklm:\Software\Microsoft\Windows\CurrentVersion\Run).Access | &("{0}{4}{2}{1}{3}" -f'ForEac','e','j','ct','h-Ob') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.RegistryRights.tostring() -match ((("{18}{22}{19}{9}{12}{3}{7}{10}{13}{5}{16}{23}{8}{11}{4}{21}{20}{0}{1}{15}{24}{14}{2}{6}{17}"-f 'akeOwne','rs','it','}C','ntrol','e','eKe','r','e','missions','ea','y{0}FullCo','{0','t','0}Wr','hi','Su','y','Chang','er','tValue{0}T','{0}Se','eP','bK','p{'))  -F  [char]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.RegistryRights.tostring(); &("{1}{0}"-f 'rite','W') ('Gro'+'up'+': '+"$arg, "+'Permissi'+'ons:'+' '+"$rights "+'o'+'n '+('hklm:{0}'+'Soft'+'war'+'e{0}Mic'+'r'+'o'+'s'+'oft'+'{0}W'+'ind'+'ows{0}C'+'u'+'rre'+'n'+'t'+'Ve'+'rsion{0}'+'R'+'un') -f  [CHAr]92) } } }
        $result += (&("{1}{0}"-f '-Acl','Get') hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce).Access | &("{0}{3}{2}{4}{1}"-f'F','ect','rEach','o','-Obj') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.RegistryRights.tostring() -match ((("{8}{16}{19}{22}{17}{9}{15}{1}{0}{5}{13}{6}{4}{2}{21}{7}{14}{10}{20}{11}{12}{18}{3}{23}" -f'l8lsS','ontro','ue8','Ke','l','e','Va','sT','Chan','SubKey8lsF','r','hip8','ls','t','akeOwne','ullC','gePer','eate','Write','missions8l','s','l','sCr','y')).rEPLaCe(([ChAR]56+[ChAR]108+[ChAR]115),[STrinG][ChAR]124)) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.RegistryRights.tostring(); &("{0}{1}"-f'W','rite') ('Group:'+' '+"$arg, "+'P'+'erm'+'issions: '+"$rights "+'o'+'n '+('hklm:{'+'0}Softwar'+'e{0}M'+'icrosof'+'t{0}Wind'+'ow'+'s{0'+'}Cu'+'rrentVer'+'sion{0'+'}Run'+'Once')-f [ChAR]92) } } }
        $result += &("{2}{3}{1}{0}"-f'erty','ItemProp','G','et-') -Path hklm:\Software\Microsoft\Windows\CurrentVersion\Run | &("{2}{1}{0}" -f't','ach-Objec','ForE') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{6}{7}{3}{5}{8}{0}{2}{1}{4}"-f'e','She','r','oft.','ll.Core*','P','Micr','os','ow')) { Break } If ($obj -like ((("{1}{0}"-f'*','SpZ*SpZ'))-rePlace([cHAr]83+[cHAr]112+[cHAr]90),[cHAr]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}" -f '*','* -')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}"-f '*','* /')) { $o = $obj.split('/')[0] } Else { $o = $obj } (&("{0}{1}"-f 'Get-A','cl') $o).Access } } | &("{2}{0}{1}"-f 'c','h-Object','ForEa') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{5}{1}{11}{4}{27}{3}{15}{22}{24}{23}{28}{31}{10}{12}{29}{14}{13}{20}{19}{30}{6}{8}{32}{7}{35}{9}{0}{26}{33}{21}{18}{25}{16}{17}{34}{2}"-f'8','pe','824','}ChangePermissio','a','Ap','akeOw','i','ners','6','ies{0}C','ndD','rea','0}','s{','n','{0}','107','}-','od','FullControl{0}M','56{0','s{0}Cre','Di','ate','536805376','43','ta{0','re','teFile','ify{0}T','ctor','h','54','3741','p{0}Write{0}WriteData{0}2'))-f  [char]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}" -f 'te','Wri') ('Gro'+'up: '+"$arg, "+'Permiss'+'ions'+': '+"$rights "+'on'+' '+"$o") } } }
        $result += &("{0}{2}{1}{3}" -f'G','op','et-ItemPr','erty') -Path hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce | &("{1}{2}{0}"-f'rEach-Object','F','o') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{0}{5}{1}{2}{4}{3}" -f'Mic','PowerShe','ll.Co','e*','r','rosoft.')) { Break } If ($obj -like ((("{1}{0}{2}" -f'H','Hb2*','b2*')).replace('Hb2',[sTrINg][ChAr]34))) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}"-f ' -*','*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{0}{1}" -f'*',' /*')) { $o = $obj.split('/')[0] } Else { $o = $obj } (&("{1}{0}" -f'l','Get-Ac') $o).Access } } | &("{0}{1}{2}" -f'ForEach-','Ob','ject') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{20}{3}{8}{16}{4}{11}{26}{23}{24}{7}{17}{25}{15}{1}{2}{27}{29}{5}{0}{22}{21}{9}{14}{30}{10}{6}{12}{19}{13}{28}{18}" -f 'e{0','ify{0}TakeOwner','s','{0}Chan','D','Writ','8','eFi','ge','ata{','6{0}-536','i','05','6{0}107374','0}','od','Permissions{0}Create','les{0}FullContr','4','37','AppendData','eD','}Writ','ctorie','s{0}Creat','ol{0}M','re','hi','182','p{0}','26843545'))  -f[ChAR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}" -f'Wr','ite') ('Grou'+'p: '+"$arg, "+'Permis'+'s'+'ions: '+"$rights "+'o'+'n '+"$o") } } }
        $result += &("{2}{0}{1}"-f'It','emProperty','Get-') -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\Run | &("{1}{2}{3}{0}{4}" -f '-Objec','F','orEa','ch','t') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{5}{0}{1}{4}{3}{2}{6}"-f'croso','f','ll.Co','he','t.PowerS','Mi','re*')) { Break } If ($obj -like ((("{0}{1}" -f'sz','f*szf*'))-REPLAce([cHAR]115+[cHAR]122+[cHAR]102),[cHAR]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}"-f' -*','*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}"-f' /*','*')) { $o = $obj.split('/')[0] } Else { $o = $obj } (&("{1}{0}{2}"-f't','Ge','-Acl') $o).Access } } | &("{2}{1}{3}{0}" -f 'ect','Each','For','-Obj') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{32}{1}{26}{9}{3}{24}{23}{19}{42}{46}{35}{44}{16}{43}{18}{30}{47}{34}{37}{41}{11}{12}{36}{38}{10}{27}{5}{25}{7}{17}{14}{33}{13}{28}{22}{21}{45}{0}{20}{31}{15}{39}{8}{2}{4}{6}{29}{40}" -f'X8wWri','ppe','435','Per','456','X','X8w-5368','i','w268','DataX8wChange','nt','w','Ful','eOw','Ta','ataX','riesX8wCr','fyX8w','at','e','te','ip','h','Cr','missionsX8w','8wMod','nd','rol','ners','05','eFi','D','A','k','s','e','lC','X','o','8','376X8w1073741824','8','a','e','cto','X8wWrite','teDir','le')).ReplACe(([chAr]88+[chAr]56+[chAr]119),'|')) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}"-f 'Wr','ite') ('Group'+': '+"$arg, "+'Pe'+'rmissi'+'on'+'s: '+"$rights "+'on'+' '+"$o") } } }
        $result += &("{2}{3}{1}{0}"-f'erty','Prop','Get','-Item') -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\RunOnce | &("{1}{2}{3}{0}{4}"-f'-Obje','ForE','ac','h','ct') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{4}{2}{1}{3}{0}" -f'hell.Core*','soft.Power','icro','S','M')) { Break } If ($obj -like ((("{0}{2}{1}"-f'zCV*z','V*','C'))-CrePlAce([CHAr]122+[CHAr]67+[CHAr]86),[CHAr]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{0}{1}"-f'* -','*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{0}{1}" -f '*',' /*')) { $o = $obj.split('/')[0] } Else { $o = $obj } (&("{0}{1}{2}"-f 'Ge','t-Ac','l') $o).Access } } | &("{2}{0}{4}{1}{3}" -f'r','ch','Fo','-Object','Ea') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{21}{22}{23}{12}{26}{13}{34}{11}{10}{29}{6}{25}{18}{31}{2}{20}{9}{33}{19}{27}{8}{35}{15}{17}{0}{36}{28}{7}{16}{14}{24}{30}{4}{5}{1}{3}{32}"-f 'keO','6','Cre','{','5','37','teDirecto','0}Write{0}WriteData{0','tro','eFil','}Cre','0','C','ermiss','4','odify','}268','{0}Ta','i','s{0}F','at','Ap','pend','Data{0}','35456','r','hangeP','ullCon','{','a','{0}-53680','es{0}','0}1073741824','e','ions{','l{0}M','wnership'))  -f[cHaR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}" -f'e','Writ') ('Gro'+'up: '+"$arg, "+'Permis'+'sio'+'ns: '+"$rights "+'on'+' '+"$o") } } }
        if ($result -ne $null) { &("{1}{0}"-f'te','Wri') $result | &("{0}{1}" -f'So','rt') -Unique } else { &("{0}{1}" -f'W','rite') ("{1}{0}{5}{10}{8}{4}{6}{11}{7}{3}{9}{2}" -f' se','Permissions','oups.','e correc','p','t on sta',' ','es ar','tu','t for all gr','r','executabl') }


        &("{1}{0}" -f'ite','Wr') ""
        &("{0}{1}"-f'Wr','ite') ("{1}{3}{8}{11}{2}{13}{0}{9}{6}{7}{5}{4}{12}{10}" -f '-----','--','--','--------','-','-----','--','------','----','-','--------------------','-','--------','-----')
        &("{1}{0}"-f'rite','W') ""


        &("{0}{1}" -f 'Wri','te') ("{2}{6}{8}{9}{1}{7}{12}{10}{0}{4}{5}{11}{3}" -f's - try DL','cutables direc','St','n:','L in','ject','a','tory perm','rtup ','exe','n','io','issio')
        $result = $null
        $result = &("{3}{0}{2}{1}"-f 'et-I','emProperty','t','G') -Path hklm:\Software\Microsoft\Windows\CurrentVersion\Run | &("{2}{0}{3}{1}"-f 'Eac','ect','For','h-Obj') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{3}{4}{0}{2}{1}"-f'ow','e*','erShell.Cor','Microsoft.','P')) { Break } If ($obj -like ((("{2}{1}{0}" -f '6KB*','B*','6K')).rEPlaCE('6KB',[striNG][ChaR]34))) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{0}{1}"-f '* -','*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}" -f'/*','* ')) { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (&("{1}{0}"-f 'et-Acl','G') $o).Access } } | &("{3}{0}{1}{2}" -f'ch-','Obje','ct','ForEa') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{36}{16}{4}{12}{6}{34}{31}{22}{28}{21}{13}{19}{2}{7}{20}{11}{0}{32}{27}{29}{26}{5}{30}{33}{14}{25}{24}{1}{9}{10}{3}{17}{8}{18}{23}{35}{15}"-f 'FullCo','T6lWriteDa','T6lCreateF','26843','dD','sh','l','ile','l-','taT','6l','T6l','ataT6','Cr','Wr','824','en','5456T6','5368053','eateDirectories','s','T6l','ssio','76T6l107','te','i','eOwner','trolT6lModif','ns','yT6lTak','ipT','ermi','n','6l','ChangeP','3741','App'))-CrEPLAce'T6l',[cHAR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}"-f'Writ','e') ('G'+'ro'+'up: '+"$arg, "+'Pe'+'r'+'missio'+'ns:'+' '+"$rights "+'on'+' '+"$o") } } }
        $result += &("{2}{0}{4}{3}{1}"-f 'emProp','y','Get-It','rt','e') -Path hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce | &("{4}{2}{1}{0}{3}" -f 'Ob','-','ach','ject','ForE') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{1}{2}{5}{6}{4}{3}{0}{7}" -f'l','Microso','ft','e','h','.P','owerS','l.Core*')) { Break } If ($obj -like ((("{0}{1}"-f 'kE1','*kE1*')) -CREplAce  'kE1',[cHaR]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{0}{1}"-f'* ','-*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}" -f '/*','* ')) { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (&("{0}{1}" -f'Get-Ac','l') $o).Access } } | &("{4}{1}{3}{2}{0}" -f 'ject','E','-Ob','ach','For') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{12}{9}{5}{14}{21}{20}{15}{2}{11}{6}{24}{19}{22}{23}{13}{16}{8}{0}{18}{7}{3}{4}{17}{1}{10}" -f 'w','6y1l-536805376y1','io','1lWriteDa','t','pendDatay','ea','y','akeO','p','l1073741824','nsy1lCr','A','llControly1lModifyy','1lCha','rmiss','1lT','ay1l26843545','nershipy1lWrite','or','ePe','ng','iesy1lCreateFilesy1lF','u','teDirect'))-cREPLAcE([Char]121+[Char]49+[Char]108),[Char]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}" -f 'ite','Wr') ('Gr'+'oup:'+' '+"$arg, "+'Perm'+'i'+'ssio'+'ns: '+"$rights "+'on'+' '+"$o") } } }
        $result += &("{4}{3}{0}{1}{2}"-f 't','em','Property','t-I','Ge') -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\Run | &("{1}{2}{0}"-f'ect','ForEac','h-Obj') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{3}{5}{4}{1}{0}{6}{2}" -f 'ell.Cor','Sh','*','Micro','ft.Power','so','e')) { Break } If ($obj -like ((("{0}{1}{2}"-f '4','Cm*4C','m*'))  -RePlACe '4Cm',[cHar]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}" -f'*','* -')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}"-f '*','* /')) { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (&("{0}{1}" -f 'Get','-Acl') $o).Access } } | &("{4}{2}{0}{3}{1}" -f 'rEach','Object','o','-','F') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{13}{14}{11}{18}{28}{20}{6}{25}{26}{19}{21}{1}{5}{3}{4}{23}{2}{24}{7}{22}{12}{10}{8}{0}{9}{27}{16}{15}{17}"-f'2684354','ate','difyOXBTake','O','XBF','Files','OX','ipOXBWrit','DataOXB','56OXB-536','e','dDataOX','OXBWrit','Appe','n','8','5376OXB1073741','24','B','r','ns','e','e','ullControlOXBMo','Ownersh','B','CreateDirectoriesOXBC','80','ChangePermissio')).rEplACe('OXB','|')) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}"-f 'rite','W') ('Grou'+'p: '+"$arg, "+'Pe'+'r'+'m'+'is'+'sions: '+"$rights "+'o'+'n '+"$o") } } }
        $result += &("{3}{2}{0}{1}"-f 'oper','ty','r','Get-ItemP') -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\RunOnce | &("{1}{2}{0}{4}{3}"-f 'b','ForEac','h-O','ct','je') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{2}{3}{8}{1}{4}{0}{6}{7}{5}"-f'Power','t','Mic','r','.','Core*','Shell','.','osof')) { Break } If ($obj -like ((("{2}{1}{0}" -f'*','Ra','gRa*g'))  -rePlaCe'gRa',[char]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}" -f '*','* -')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}" -f '*','* /')) { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (&("{0}{2}{1}" -f'G','cl','et-A') $o).Access } } | &("{4}{1}{0}{2}{3}" -f '-','Each','Ob','ject','For') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{7}{21}{15}{37}{41}{12}{9}{33}{17}{40}{16}{27}{23}{19}{5}{28}{0}{32}{38}{25}{36}{30}{10}{35}{34}{24}{39}{14}{18}{20}{3}{42}{1}{4}{31}{2}{13}{22}{29}{8}{11}{26}{6}"-f'fy{','{0}','536','e','26','reateFil','24','A','6{','C','nersh','0}10737','0}','805','Write{0}W','e','{0}Crea','missi','ri','ries{0}C','t','pp','3','ecto','0','k','418','teDir','es{0}FullControl{0}Modi','7','w','8435456{0}-','0','hangePer','p{','i','eO','ndDa','}Ta','}','ons','ta{','Data')) -f  [cHAr]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}" -f 'e','Writ') ('G'+'roup: '+"$arg, "+'P'+'ermissions:'+' '+"$rights "+'o'+'n '+"$o") } } }
        if ($result -ne $null) { &("{0}{1}"-f'W','rite') $result | &("{0}{1}"-f 'Sor','t') -Unique } else { &("{1}{0}"-f 'ite','Wr') ("{10}{0}{15}{12}{9}{13}{6}{4}{2}{1}{3}{7}{14}{8}{11}{16}{5}"-f 'ermi','ectorie','ir','s','s d','ps.','le',' are',' f',' ex','P','or all','tup','ecutab',' correct','ssions set on star',' grou') }
            

        &("{1}{0}" -f 'rite','W') ""
        &("{1}{0}"-f 'te','Wri') ("{13}{4}{12}{3}{10}{1}{9}{0}{11}{8}{2}{5}{6}{7}" -f '--','-----','------','-','-','-----','---------','----','--','--','-----','-------','---------','------------')
        &("{1}{0}"-f 'e','Writ') ""


        &("{1}{0}" -f 'te','Wri') (("{21}{24}{16}{20}{0}{5}{9}{22}{23}{12}{18}{2}{13}{10}{14}{1}{17}{6}{11}{8}{15}{3}{19}{4}{7}"-f'on','b','y k','ry p','h','s on u','c','s):','bi','nins','y','hanging ','reg','e','s and su','na','s','keys (','ist','at','si','Check','tall',' ','ing permi'))
        $result = $null
        $result = &("{1}{2}{3}{0}" -f 'm','Get','-C','hildIte') HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -Recurse 2> $null | &("{3}{2}{0}{1}"-f 'c','t','bje','ForEach-O') { $o = $_.Name; (&("{0}{2}{1}" -f 'Get-A','l','c') -Path Registry::$_).Access } | &("{2}{3}{0}{1}" -f 'Obj','ect','ForEa','ch-') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.RegistryRights.tostring() -match ((("{7}{14}{13}{8}{2}{9}{20}{15}{11}{1}{3}{12}{10}{17}{16}{19}{5}{0}{4}{18}{6}" -f 'rsh','ntrolY','Cr','gESe','ipYgEWr','ne','teKey','Chan','nsYgE','eateSub','eYg','EFullCo','tValu','ssio','gePermi','Yg','e','ETak','i','Ow','Key')) -cREPlAcE([char]89+[char]103+[char]69),[char]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.RegistryRights.tostring(); &("{1}{0}"-f 'ite','Wr') ('Grou'+'p'+': '+"$arg, "+'Permissio'+'n'+'s: '+"$rights "+'o'+'n '+"$o") } } }
        if ($result -ne $null) { &("{0}{1}"-f 'W','rite') $result | &("{1}{0}"-f'rt','So') -Unique } else { &("{1}{0}"-f 'rite','W') ("{5}{12}{4}{14}{10}{15}{6}{0}{8}{7}{19}{13}{1}{17}{16}{11}{18}{3}{9}{2}"-f 'l','keys ','ups.',' all g','i','Per','ta',' registry keys','l','ro','ns s','orrect','m','ub','ssio','et on unins',' c','are',' for',' and s') }


        &("{0}{1}" -f'Writ','e') ""
        &("{0}{1}"-f'Writ','e') ("{1}{6}{5}{13}{11}{15}{9}{7}{3}{14}{8}{4}{10}{2}{12}{0}" -f '---','--------','---','--------','--','-','----','------','-----','--------','---','----','--------','-','-','-----')
        &("{0}{1}" -f 'W','rite') ""


        &("{0}{1}" -f'Writ','e') ("{1}{7}{8}{3}{2}{6}{10}{0}{5}{9}{4}" -f 'Y_P','Checking ','ge','- chan','AME of a service:','ATH_',' BI','services permis','sions ','N','NAR')
        $result = $null
        $result = &("{1}{2}{0}" -f 'ce','Get-Se','rvi') | &("{1}{0}{2}"-f'l','Se','ect') Name | &("{1}{0}{2}" -f 'b','ForEach-O','ject') { ForEach ($name in $_.Name) { Trap { Continue } $privs = ((&("{0}{1}" -f 'sc','.exe') sdshow $name) | &("{0}{2}{1}" -f 'Out','ng','-Stri') | &("{2}{3}{1}{4}{0}" -f'-SDDL','ertFro','C','onv','m') 2> $null); &("{1}{0}"-f 'ite','Wr') $privs.Access } } | &("{3}{2}{1}{0}" -f 't','ach-Objec','orE','F') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.Rights.tostring() -match ((("{7}{8}{5}{3}{13}{12}{11}{2}{9}{1}{0}{4}{6}{10}" -f 'Wr','5','e','Control','ite PB5Wr','rmissionsPB5Full','i','ChangeP','e',',PB','teData','hipPB5Writ','B5ModifyPB5TakeOwners','P'))-RePlAce 'PB5',[chAR]124) -and $_.IdentityReference.tostring() -like "*\$arg" -and $_.AccessControlType.tostring() -match ("{0}{1}"-f'Al','low')) { $rights = $_.Rights.tostring(); &("{0}{1}" -f'W','rite') ('Grou'+'p: '+"$arg, "+'Per'+'m'+'issio'+'n'+'s: '+"$rights "+'on'+' '+"$name") } } }
        if ($result -ne $null) { &("{0}{1}"-f 'W','rite') $result | &("{1}{0}"-f 'ort','S') -Unique } else { &("{1}{0}" -f 'rite','W') ("{22}{4}{26}{8}{21}{6}{14}{7}{15}{9}{17}{25}{13}{18}{19}{20}{2}{11}{5}{23}{1}{0}{3}{24}{12}{10}{16}" -f'ow a','e A as All',' of ','t ','r','o','e cor','fo','sions set on ',' a','ng','SDDL sh','e beginni',' Doub','rect ','r','.','ll grou','le',' check - each par','t','services ar','Pe','uld hav','th','ps.','mis') }
        

        &("{0}{1}"-f 'Wr','ite') ""
        &("{0}{1}" -f 'Wr','ite') ("{9}{5}{4}{12}{3}{6}{14}{7}{8}{10}{15}{11}{13}{0}{2}{1}"-f'----','-','--','--','--','--------','---------','----','--','-----','-------','------','-------','--','-------','--')
        &("{1}{0}" -f'rite','W') ""


        &("{1}{0}" -f'rite','W') (("{7}{9}{16}{5}{18}{4}{19}{13}{8}{17}{6}{3}{15}{2}{11}{1}{12}{14}{20}{21}{10}{0}"-f'):','alu','d subkeys','k','s ','ss','isty ','C','vices ','hecki','e',' (changing ImagePath v','e of','er',' a ser','eys an','ng permi','reg','ion','on s','v','ic'))
        $result = $null
        $result = &("{2}{3}{1}{0}" -f 'm','ildIte','G','et-Ch') hklm:\System\CurrentControlSet\services -Recurse 2> $null | &("{0}{3}{2}{1}"-f'ForE','ject','h-Ob','ac') { $o = $_.Name; (&("{0}{1}" -f'Get','-Acl') -Path Registry::$_).Access } | &("{1}{2}{3}{0}" -f'ject','ForE','ac','h-Ob') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.RegistryRights.tostring() -match ((("{18}{2}{14}{22}{19}{9}{12}{21}{25}{8}{16}{7}{11}{10}{15}{6}{17}{4}{5}{23}{13}{3}{20}{1}{0}{24}" -f 'e','teK','s','p','e','O','ej','trolj','ullCo','t','SetV','nr','eSubKe','shi','sio','alu','n','nrTak','ChangePermi','Crea','jnrWri','y','nsjnr','wner','y','jnrF')).rEpLacE(([CHAR]106+[CHAR]110+[CHAR]114),[strIng][CHAR]124)) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.RegistryRights.tostring(); &("{0}{1}" -f 'Writ','e') ('G'+'roup:'+' '+"$arg, "+'Perm'+'issio'+'n'+'s: '+"$rights "+'on'+' '+"$o") } } }
        if ($result -ne $null) { &("{1}{0}" -f 'te','Wri') $result | &("{0}{1}" -f 'Sor','t') -Unique } else { &("{0}{1}" -f 'Wri','te') ("{6}{15}{7}{9}{3}{8}{1}{5}{10}{2}{14}{12}{11}{4}{13}{0}"-f 'll groups.','i','ys are co','s ','t for','stry keys and','Permiss','ns set on s','reg','ervice',' subke','c','e',' a','rr','io') }


        &("{1}{0}"-f 'te','Wri') ""
        &("{0}{1}"-f'W','rite') ("{5}{6}{1}{3}{0}{11}{10}{2}{14}{9}{12}{15}{7}{4}{8}{13}"-f '------','------','--','---','----','----','---','----','-------','--','----','-','-----','----','--------------','-')
        &("{0}{1}"-f'Wri','te') ""


        &("{1}{0}"-f'ite','Wr') ("{0}{8}{2}{6}{1}{4}{3}{10}{7}{9}{5}"-f 'Se','ck','ary permissions -','ser','door ','ary:',' ba','ce','rvice bin',' bin','vi')
        $result = $null
        $result = &("{1}{4}{3}{2}{0}"-f'tem','Ge','I','ild','t-Ch') hklm:\System\CurrentControlSet\services 2> $null | &("{0}{1}{3}{2}" -f'ForE','ac','bject','h-O') { &("{2}{1}{0}{3}"-f 'Propert','t-Item','Ge','y') -Path Registry::$_ -Name ImagePath 2> $null } | &("{4}{2}{1}{3}{0}"-f 't','ch-Obj','orEa','ec','F') { Trap { Continue } $obj = $_.ImagePath; If ($obj -like ("{0}{1}{3}{5}{6}{4}{2}"-f 'Mi','c','.Core*','ro','owerShell','s','oft.P')) { Break } If ($obj -like ((("{0}{1}{2}"-f'{0}*{','0','}*')) -f  [ChAR]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}" -f' -*','*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}" -f '/*','* ')) { $o = $obj.split('/')[0] } Else { $o = $obj } (&("{0}{1}{2}" -f 'Get','-Ac','l') $o 2> $null).Access } | &("{1}{0}{2}"-f 'jec','ForEach-Ob','t') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{6}{34}{26}{14}{30}{0}{12}{2}{16}{37}{36}{10}{7}{21}{13}{23}{22}{17}{24}{8}{32}{5}{15}{33}{20}{29}{9}{28}{3}{18}{1}{19}{35}{11}{4}{31}{38}{25}{27}"-f'on','Data9','e','rit','5','ol9czModi','A','zC','lCo','9','9c','43','s9czCreat','a','rmis','fy9czTakeOw','D','s9','e','cz','ship','re','ile','teF','czFul','53769cz1','czChangePe','073741824','czW','9czWrite','si','4569cz-5368','ntr','ner','ppendData9','268','rectories','i','0')).rePlaCe(([CHar]57+[CHar]99+[CHar]122),[stRIng][CHar]124)) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}"-f'te','Wri') ('G'+'rou'+'p: '+"$arg, "+'Permissi'+'on'+'s'+': '+"$rights "+'on'+' '+"$o") } } }
        if ($result -ne $null) { &("{1}{0}"-f 'rite','W') $result } else { &("{0}{1}"-f 'Writ','e') ("{1}{2}{7}{9}{13}{6}{0}{12}{4}{10}{5}{8}{3}{11}" -f'ice ','Pe','rmi',' groups','ect for ','l',' on serv','s','l','sion','a','.','binaries are corr','s set') }
           

        &("{0}{1}"-f'Wri','te') ""
        &("{1}{0}" -f'te','Wri') ("{13}{11}{12}{16}{4}{14}{5}{6}{9}{15}{2}{1}{7}{0}{8}{10}{3}"-f'--','-','-','-------','--','-','----------------','-','--','---','---','--------','-','------','-','--------','-------')
        &("{0}{1}"-f'Writ','e') ""


        &("{0}{1}" -f 'Writ','e') ("{9}{8}{0}{10}{6}{1}{5}{7}{3}{4}{2}"-f 'ice direct',' ','n:','ct','io','permissions - try DLL in','ry','je','erv','S','o')
        $result = $null
        $result = &("{3}{2}{1}{0}{4}"-f'ildIte','h','-C','Get','m') hklm:\System\CurrentControlSet\services 2> $null | &("{3}{0}{1}{4}{2}" -f'orEa','ch-','ect','F','Obj') { &("{1}{0}{2}" -f 'r','Get-ItemPrope','ty') -Path Registry::$_ -Name ImagePath 2> $null } | &("{3}{1}{2}{0}" -f'-Object','o','rEach','F') { Trap { Continue } $obj = $_.ImagePath; If ($obj -like ("{4}{5}{2}{1}{3}{0}"-f'.Core*','wer','soft.Po','Shell','Mic','ro')) { Break } If ($obj -like ((("{2}{0}{1}" -f'{','0}*','{0}*'))-f[cHAr]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}" -f '*','* -')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}"-f '*','* /')) { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (&("{0}{1}" -f'Get-A','cl') $o 2> $null).Access } | &("{2}{3}{0}{1}" -f'ach-','Object','F','orE') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{34}{26}{35}{24}{17}{2}{31}{16}{10}{15}{4}{20}{13}{5}{29}{25}{12}{9}{6}{11}{23}{19}{30}{8}{37}{3}{32}{7}{21}{36}{28}{18}{33}{27}{0}{1}{14}{22}"-f'6Jra','10','mi','Writ','ori','ont','yJr','Jr','ers','f','raCreateDir','aT','i','JraFullC','737','ect','ionsJ','taJraChangePer','t','keO','esJraCreateFiles','aWr','41824','a','Da','lJraMod','e','680537','eDa','ro','wn','ss','e','aJra268435456Jra-53','App','nd','it','hipJra')) -creplaCE 'Jra',[cHAr]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}"-f'Wr','ite') ('Gr'+'oup'+': '+"$arg, "+'Permiss'+'ions'+': '+"$rights "+'on'+' '+"$o") } } }
        if ($result -ne $null) { &("{0}{1}"-f 'Wri','te') $result | &("{0}{1}" -f 'S','ort') -Unique } else { &("{1}{0}"-f'e','Writ') ("{4}{13}{0}{12}{6}{15}{5}{3}{14}{7}{11}{9}{16}{8}{10}{2}{1}" -f 'issio','ps.','rou','ice d','Pe','rv','t on','ctories ar',' ','orre','for all g','e c','ns se','rm','ire',' se','ct') }
            

        &("{0}{1}"-f'W','rite') ""
        &("{0}{1}"-f 'W','rite') ("{5}{14}{12}{16}{20}{8}{7}{15}{10}{6}{11}{17}{18}{1}{2}{0}{13}{3}{19}{4}{9}" -f'----','--','----','-------','-','---','-','-','----','---','-','-------','-','---','----','------','-','-','------','--','--------')
        &("{0}{1}" -f'Writ','e') ""

            
        &("{1}{0}" -f 'te','Wri') ("{3}{4}{10}{6}{2}{0}{5}{7}{9}{8}{1}" -f 'si',':','rmis','Pr','oce','on','e','s - backdoor ','s binary','proces','ss binary p')
        $result = $null
        $result = &("{1}{0}{3}{2}"-f'et-','G','cess','Pro') | &("{0}{4}{2}{1}{3}" -f 'F','c','Ea','h-Object','or') { ForEach ($proc in $_.path) { (&("{0}{1}{2}"-f 'Ge','t','-Acl') $proc).Access } } | &("{2}{0}{1}" -f 'rEach-Objec','t','Fo') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{5}{11}{17}{0}{23}{22}{2}{14}{24}{18}{20}{13}{19}{8}{3}{4}{15}{7}{10}{12}{21}{1}{9}{16}{6}"-f '{0}Ch','}268435456{0}-5','s{0}','ntr','ol{0}Mod','Appen','741824','fy{0}','ullCo','3','Take','d','Ownership{0}Write{0}WriteD','ateFile','C','i','6805376{0}1073','Data','ectories{','s{0}F','0}Cre','ata{0','ission','angePerm','reateDir')) -F[char]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}"-f'Writ','e') ('Grou'+'p'+': '+"$arg, "+'Per'+'mis'+'si'+'ons: '+"$rights "+'on'+' '+"$proc") } } }
        if ($result -ne $null) { &("{0}{1}" -f'Writ','e') $result | &("{1}{0}"-f 't','Sor') -Unique } else { &("{0}{1}"-f 'W','rite') ("{9}{1}{3}{0}{2}{6}{10}{15}{12}{11}{7}{5}{14}{13}{4}{8}"-f 's','e','et ','rmissions ','for al','ries are co','on pr','ina','l groups.','P','oce','b',' ','t ','rrec','ss') }
            

        &("{0}{1}" -f 'Wri','te') ""
        &("{0}{1}" -f'W','rite') ("{8}{0}{1}{6}{7}{5}{2}{4}{15}{9}{3}{14}{12}{10}{11}{13}"-f '-','-------','------------','---','----','--','---','---','-','---','-----','--','-----','--','--------------','---')
        &("{0}{1}"-f 'Wr','ite') ""

            
        &("{1}{0}" -f 'te','Wri') ("{10}{4}{8}{5}{6}{2}{1}{3}{7}{0}{9}"-f'DLL ','ssion','i','s','ro','ess dir','ectory perm',' - try ','c','injection:','P')
        $result = $null
        $result = &("{0}{1}{3}{2}"-f 'Get-','P','ess','roc') | &("{4}{1}{2}{0}{3}"-f '-Obj','Ea','ch','ect','For') { ForEach ($proc in $_.path) { $o = $proc.Split("\"); $proc = $o[0..($o.Length-2)] -join ("\"); (&("{1}{0}"-f'l','Get-Ac') $proc).Access } } | &("{2}{1}{0}"-f'ct','e','ForEach-Obj') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{13}{39}{33}{3}{34}{15}{37}{5}{0}{14}{24}{2}{4}{22}{30}{25}{31}{32}{38}{18}{27}{10}{28}{16}{21}{23}{12}{11}{8}{17}{1}{19}{26}{36}{9}{6}{29}{35}{20}{7}" -f 'sio','px','irec','axwu','tori','is','a','6xwu1073741824','Owne','teD','wu','Take','u','App','n','ngePe','d','rshi','trol','wuW','537','i','esxwuCreateFil','fyxw','sxwuCreateD','xw','ri','x','Mo','tax','es','uF','ull','Dat','Cha','wu268435456xwu-53680','texwuWri','rm','Con','end')).REpLACE('xwu','|')) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}"-f'Wri','te') ('G'+'ro'+'up: '+"$arg, "+'Perm'+'is'+'sions: '+"$rights "+'o'+'n '+"$proc") } } }
        if ($result -ne $null) { &("{1}{0}" -f 'te','Wri') $result | &("{0}{1}"-f 'S','ort') -Unique } else { &("{0}{1}"-f'W','rite') ("{8}{12}{5}{11}{9}{13}{14}{15}{6}{10}{18}{16}{0}{17}{4}{1}{7}{2}{3}" -f ' cor',' all gr','p','s.','t for','io','ocess director','ou','Per','s','ies','ns ','miss','et ','on ','pr','e','rec',' ar') }
            

        &("{1}{0}" -f 'te','Wri') ""
        &("{1}{0}"-f 'te','Wri') ("{15}{3}{9}{4}{11}{1}{16}{13}{8}{7}{6}{12}{2}{0}{17}{10}{18}{14}{5}" -f'---','-------','-','--','----','-','-','--------','----','--','-----','--','-------','--','--','------','------','----','---')
        &("{1}{0}"-f'rite','W') ""

            
        &("{1}{0}" -f'te','Wri') ("{9}{7}{10}{5}{1}{8}{6}{3}{2}{4}{0}"-f 'y:','i','kdoor bi','bac','nar','ss b',' - ','duled proc','nary permissions','Sche','e')
        $result = $null
        $result = &("{1}{0}{2}" -f'task','sch','s') /query /fo LIST /V | &("{0}{1}{2}" -f'fin','ds','tr') "\\" | &("{1}{0}" -f 'r','findst') "\." | &('%') { Trap { Continue } $o = $_.Split(" "); $obj = $o[30..($o.Length-1)] -join (" "); If ($obj -like ((("{1}{2}{0}"-f '*','y','Iq*yIq'))-cReplace([Char]121+[Char]73+[Char]113),[Char]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}" -f' -*','*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}"-f'*','* /')) { $o = $obj.split('/')[0] } Else { $o = $obj }; If ($o -like ("{1}{0}" -f'*%*','*%')) { $var = $o.split('%')[1]; $out = &("{1}{0}" -f 'olve','res')($var); $o = $o.replace("%$var%",$out) }; (&("{1}{0}" -f'et-Acl','G') $o 2> $null).Access } | &("{3}{2}{0}{1}" -f 'jec','t','ach-Ob','ForE') { Trap { Continue } ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{40}{27}{15}{5}{34}{6}{1}{17}{38}{36}{41}{18}{3}{4}{0}{2}{37}{33}{16}{39}{32}{29}{9}{21}{13}{22}{19}{23}{7}{10}{12}{11}{24}{25}{31}{20}{35}{26}{8}{30}{14}{28}"-f 'Fu','Permi','ll','esjOpC','reateFilesjOp','DatajOpCh','ge','t','Op','Op','ejOpW','teDa','ri','akeO','73','d','roljOpM','ss','rectori','r','68','T','wnershipjOpW','i','t','ajO','536805376j','ppen','741824','yj','10','p2','dif','t','an','435456jOp-','onsjOp','Con','i','o','A','CreateDi')).replaCe('jOp','|')) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}" -f'Wr','ite') ('Gr'+'ou'+'p: '+"$arg, "+'Pe'+'rmi'+'ssi'+'ons:'+' '+"$rights "+'on'+' '+"$o") } } }
        if ($result -ne $null) { &("{1}{0}"-f'e','Writ') $result | &("{0}{1}" -f'S','ort') -Unique } else { &("{0}{1}"-f'Wri','te') ("{15}{14}{11}{0}{13}{4}{7}{1}{5}{12}{10}{17}{3}{6}{16}{8}{2}{9}" -f 'ns ','n s','grou','ct','t ','chedule',' f','o',' ','ps.','are','sio','d binaries ','se','is','Perm','or all',' corre') }
            

        &("{1}{0}"-f'te','Wri') ""
        &("{1}{0}" -f 'rite','W') ("{2}{13}{12}{10}{8}{4}{0}{5}{6}{7}{14}{15}{1}{11}{3}{9}"-f '-','--------','----','--','-------','-','-----','----','------','---------','---','-','--','---','-','-------------')
        &("{1}{0}" -f 'e','Writ') ""

            
        &("{1}{0}"-f'rite','W') ("{10}{16}{3}{1}{11}{8}{12}{2}{13}{14}{4}{5}{9}{6}{7}{0}{15}"-f 'o','roce','m','p','- try DL','L','inject','i','ectory',' ','Schedul','ss dir',' per','issio','ns ','n:','ed ')
        $result = $null
        $result = &("{2}{0}{1}" -f 'cht','asks','s') /query /fo LIST /V | &("{0}{1}{2}"-f 'f','indst','r') "\\" | &("{1}{0}"-f'ndstr','fi') "\." | &('%') { Trap { Continue } $o = $_.Split(" "); $obj = $o[30..($o.Length-1)] -join (" "); If ($obj -like ((("{0}{1}{2}"-f 'fNT','*','fNT*')).REPlACe('fNT',[sTRInG][cHar]34))) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}" -f '-*','* ')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{0}{1}"-f'*',' /*')) { $o = $obj.split('/')[0] } Else { $o = $obj }; If ($o -like ("{0}{1}" -f '*%','*%*')) { $var = $o.split('%')[1]; $out = &("{0}{2}{1}" -f 're','e','solv')($var); $o = $o.replace("%$var%",$out) }; $obj = $o.Split("\"); $o = $obj[0..($obj.Length-2)] -join ("\"); (&("{0}{2}{1}" -f'Ge','Acl','t-') $o 2> $null).Access } | &("{0}{2}{1}"-f 'ForE','ect','ach-Obj') { Trap { Continue } ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{4}{7}{19}{39}{32}{10}{30}{21}{38}{14}{18}{5}{6}{26}{15}{25}{3}{28}{29}{27}{23}{37}{11}{1}{12}{22}{31}{8}{24}{33}{20}{35}{16}{36}{17}{0}{9}{2}{13}{34}" -f '680','p5m6Wr','61073','m6','App','te','Files5m','endData5m6Ch','Wr','53765m','Cre','hi','ite5','7418','ies5m6Cre','o','843','5m6-53','a','a','ta5m62','o','m','er','iteD','ntrol5','6FullC','keOwn','Modify','5m6Ta','ateDirect','6','issions5m6','a','24','6','5456','s','r','ngePerm'))  -RepLAcE '5m6',[cHAR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}" -f'Writ','e') ('Gro'+'up'+': '+"$arg, "+'P'+'ermiss'+'io'+'n'+'s: '+"$rights "+'on'+' '+"$o") } } }
        if ($result -ne $null) { &("{1}{0}"-f 'ite','Wr') $result | &("{1}{0}" -f't','Sor') -Unique } else { &("{0}{1}"-f'Wri','te') ("{10}{1}{6}{5}{7}{11}{2}{8}{13}{3}{12}{0}{9}{4}" -f'ct f','iss','binar','re','oups.','n','io','s set','y ','or all gr','Perm',' on scheduled ',' corre','directories a') }
            

        &("{0}{1}" -f'Wri','te') ""
        &("{1}{0}"-f 'e','Writ') ("{1}{10}{3}{4}{9}{2}{5}{11}{8}{0}{7}{6}"-f'-','--','----','----------','------','----','------','----------------','-','----','---------','-------')
        &("{1}{0}"-f 'te','Wri') ""

            
        &("{1}{0}" -f 'ite','Wr') ("{4}{3}{0}{6}{1}{7}{5}{2}"-f 's','sions ','kdoor DLL:','d DLL','Loade','bac',' permis','- ')
        $result = $null
        $result = ForEach ($item in (&("{2}{0}{1}{3}" -f'e','t','G','-WmiObject') -Class CIM_ProcessExecutable)) { [wmi]"$($item.Antecedent)" | &("{3}{2}{0}{1}"-f 'jec','t','-Ob','Where') {$_.Extension -eq 'dll'} | &("{2}{0}{1}" -f'lec','t','Se') Name | &("{3}{2}{0}{1}" -f 'jec','t','b','ForEach-O') { $o = $_.Name; (&("{1}{0}{2}"-f'-','Get','Acl') $o 2> $null).Access } | &("{2}{4}{3}{1}{0}" -f't','c','ForEach-','e','Obj') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{2}{11}{24}{21}{16}{20}{26}{29}{4}{3}{9}{30}{10}{19}{27}{7}{22}{8}{14}{13}{28}{31}{15}{23}{17}{6}{25}{1}{0}{12}{18}{5}"-f'376{0','456{0}-536805','AppendD','r','eateDirecto','41824','te{0}WriteData{0}','Contr','{','ie','{0','ata','}1073','}Mod','0','eOwne','mi','Wri','7','}CreateFiles{','ssions','ePer','ol','rship{0}','{0}Chang','268435','{','0}Full','ify{0','0}Cr','s','}Tak'))-f[CHaR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}"-f'ite','Wr') ('Group:'+' '+"$arg, "+'Pe'+'rmissions'+':'+' '+"$rights "+'on'+' '+"$o") } } } }
        if ($result -ne $null) { &("{1}{0}" -f 'te','Wri') $result | &("{1}{0}" -f'ort','S') -Unique } else { &("{1}{0}"-f'e','Writ') ("{8}{9}{5}{6}{4}{10}{1}{11}{7}{3}{2}{0}" -f's.','e corr','p','ou','aded ','ons ','set on lo','r','Permis','si','DLLs ar','ect for all g') }
            

        &("{1}{0}" -f'e','Writ') ""
        &("{1}{0}"-f 'rite','W') ("{13}{6}{8}{17}{1}{7}{12}{18}{16}{4}{2}{10}{3}{14}{15}{0}{5}{11}{9}"-f'-','----','-----------','---------------','-','-','-','-','-------','-','-','---','--','-','----','--','--','--','----------')
        &("{1}{0}" -f 'rite','W') ""

    }
    ElseIf ($mode -eq ("{0}{1}" -f 'fu','ll')) {
        &("{0}{1}" -f'Wr','ite') (("{18}{8}{2}{7}{15}{19}{17}{12}{14}{10}{16}{13}{6}{3}{11}{1}{5}{0}{4}{9}" -f' expl',' lo','em',' f','oits)','cal','o check',' Inform','st',':','ploit-suggest','or','indo','y t','ws-ex','ati','er.p','e w','Sy','on (us'))
        &("{1}{3}{2}{0}"-f 'o','s','f','ystemin') 2> $null
        &("{0}{2}{1}" -f'syst','o','eminf') > systeminfo_for_suggester.txt
            

        &("{1}{0}"-f'ite','Wr') ""
        &("{1}{0}" -f 'e','Writ') ("{1}{4}{17}{18}{5}{9}{7}{2}{3}{6}{0}{8}{16}{10}{11}{12}{15}{14}{13}"-f'-----','--','--','----','---','--','------','--','----','------','---------','----','-----','-','-','----','--','----','----')
        &("{1}{0}" -f'e','Writ') ""

        
        &("{1}{0}" -f'ite','Wr') ("{2}{5}{1}{3}{4}{0}{6}"-f ' ','r','Lis','on','ment','t envi','variables:')
        &("{1}{3}{2}{4}{0}"-f'Item','G','t-','e','Child') Env: | &("{1}{0}{2}"-f 'l','Format-Tab','e') -AutoSize
            

        &("{0}{1}"-f 'Writ','e') ""
        &("{1}{0}" -f 'rite','W') ("{11}{9}{3}{4}{10}{5}{8}{6}{2}{7}{0}{1}" -f'-----','--------------','---','--------','---','---','--','-','-------------','-----','------------','-')
        &("{0}{1}" -f 'Wr','ite') ""

        
        &("{0}{1}"-f'Writ','e') ("{5}{8}{7}{9}{2}{10}{1}{6}{0}{4}{3}" -f ' curren','ion','o',' user:','t','Lis',' about','i','t ','nf','rmat')
        $result = $null
        $result = (&("{1}{0}"-f 'et','n') user $whoami 2> $null) | &("{1}{2}{0}" -f 'ng','Ou','t-Stri')
        $result += (&("{0}{1}" -f 'ne','t') user $whoami /domain 2> $null) | &("{0}{1}{2}"-f'O','ut-','String')
        if ($result -like "*$whoami*") { &("{1}{0}" -f'te','Wri') $result } else { &("{0}{1}" -f'Wri','te') ("{7}{6}{1}{2}{9}{4}{5}{10}{0}{3}{8}"-f' this s','pr','obably from a','erve','a','in th','is ','User ','r.','nother dom','an') }
            

        &("{1}{0}"-f 'ite','Wr') ""
        &("{1}{0}"-f 'e','Writ') ("{17}{16}{12}{14}{5}{3}{13}{1}{9}{10}{11}{18}{6}{2}{15}{4}{0}{8}{7}"-f'--','--------','---','---','--','--','-','----','---','-----','-','--','-----','--','--------','---','----','---','---------')
        &("{0}{1}"-f 'W','rite') ""

        
        &("{0}{1}"-f'Wr','ite') ("{2}{3}{5}{1}{4}{0}" -f':','drive','List',' availab','s','le ')
        &("{1}{2}{0}"-f 'e','Get-P','SDriv') | &("{0}{1}{2}" -f 'Where','-Obj','ect') { $_.Provider -like ("{2}{0}{1}" -f 'FileSyst','em*','*') } | &("{1}{0}{3}{2}"-f 'a','Format-T','e','bl') -AutoSize
            

        &("{0}{1}"-f'Writ','e') ""
        &("{0}{1}" -f'Wr','ite') ("{11}{5}{7}{9}{8}{0}{13}{3}{6}{4}{12}{10}{1}{2}"-f'-----','-','------','---------','-','----------','----','----','--','-------','---','-','---','--------------')
        &("{1}{0}"-f'te','Wri') ""

        
        &("{1}{0}"-f 'te','Wri') ("{2}{0}{1}" -f't int','erfaces:','Lis')
        &("{0}{1}{2}" -f'ipc','onf','ig') /all
            

        &("{1}{0}"-f 'ite','Wr') ""
        &("{1}{0}" -f 'rite','W') ("{2}{15}{3}{16}{0}{9}{20}{6}{13}{7}{10}{5}{4}{12}{14}{1}{19}{17}{11}{18}{8}"-f'-','----','-','--','--','----','-------','-','---------','--','----------','---','---','----','-','--','-------','-','--','--','--')
        &("{0}{1}"-f 'W','rite') ""

           
        &("{0}{1}" -f'W','rite') ("{3}{0}{2}{1}{4}" -f 'is',' routin','t','L','g table:')
        &("{1}{0}" -f'te','rou') print
            

        &("{0}{1}"-f 'Wri','te') ""
        &("{1}{0}" -f 'e','Writ') ("{8}{3}{1}{6}{2}{0}{9}{12}{7}{5}{4}{10}{11}"-f'----------------','---','-------------------','--','--','----','-','------','-','-----','-','-','---------')
        &("{0}{1}" -f'W','rite') ""

            
        &("{1}{0}"-f 'rite','W') ("{0}{2}{4}{1}{3}" -f 'Lis','c','t AR','he:','P ca')
        &("{1}{0}" -f'p','ar') -A
            

        &("{1}{0}" -f'te','Wri') ""
        &("{1}{0}" -f'ite','Wr') ("{4}{7}{8}{11}{1}{16}{17}{14}{9}{15}{0}{2}{12}{5}{6}{10}{3}{13}" -f'-----','----','---','----','--','-','-','-----','-----','---','--','--------------','-------','-','---------','-','--','-')
        &("{0}{1}"-f'W','rite') ""

        
        &("{0}{1}"-f'Wr','ite') ("{3}{2}{4}{1}{0}" -f 'ns:','o','i','L','st connecti')
        &("{1}{0}{2}"-f'etsta','n','t') -ano
            

        &("{1}{0}"-f'e','Writ') ""
        &("{1}{0}"-f'ite','Wr') ("{18}{16}{1}{11}{14}{20}{6}{10}{13}{17}{5}{4}{0}{15}{12}{7}{3}{8}{2}{9}{19}"-f '--','---','-----','-----','----','----','-','-----','-----','-','-','--','-','-','------','-','--','------------','--','------','-')
        &("{1}{0}"-f 'e','Writ') ""

        
        &("{1}{0}" -f'e','Writ') ("{1}{4}{6}{5}{0}{3}{2}" -f'e','List ru',':','s','nning','process',' ')
        &("{2}{1}{0}" -f'-WmiObject','t','Ge') Win32_Process | &("{0}{1}"-f 'Sele','ct') Name, @{Name=("{2}{1}{0}"-f'me','serNa','U');Expression={$_.GetOwner().Domain+"\"+$_.GetOwner().User}} | &("{2}{1}{0}{3}" -f't-Objec','r','So','t') UserName, Name | &("{2}{0}{1}"-f'ormat-Ta','ble','F') -AutoSize
            

        &("{1}{0}"-f 'te','Wri') ""
        &("{0}{1}"-f'Writ','e') ("{18}{9}{2}{7}{8}{1}{17}{11}{5}{19}{0}{10}{12}{16}{4}{14}{13}{3}{20}{15}{6}"-f'--','-','-------','-----','---','-','----','--','-','-','----','-','-','---------','---','--','------','----','----','-------','--')
        &("{0}{1}"-f'Wr','ite') ""

        
        &("{1}{0}"-f 'ite','Wr') ("{2}{1}{4}{0}{5}{3}"-f 'ed','st','Li','e:',' install',' softwar')
        &("{2}{1}{3}{0}" -f 'm','t-Chil','Ge','dIte') HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | &("{1}{2}{3}{0}" -f'le','F','o','rmat-Tab') -AutoSize
        &("{1}{0}" -f'r','di') $env:PROGRAMFILES 2> $null
        $path = &("{0}{1}{2}"-f'r','es','olve')(("{2}{0}{3}{1}" -f 'gr','(x86)','Pro','amFiles'))
        &("{1}{0}" -f 'ir','d') $path 2> $null
            

        &("{1}{0}"-f'ite','Wr') ""
        &("{1}{0}" -f 'rite','W') ("{17}{3}{6}{15}{20}{16}{19}{1}{13}{4}{7}{5}{8}{18}{2}{10}{11}{12}{9}{14}{0}" -f'---','-','-','--','----','--','----','-','--','-','---------------','-','--','----','-','-','---------','----','------','--','----')
        &("{0}{1}" -f'Wri','te') ""

        
        &("{0}{1}"-f'W','rite') ("{5}{6}{4}{3}{1}{2}{0}"-f 'vers:','ed dr','i','l','stal','List ','in')
        &("{2}{1}{0}" -f 'ry','ue','driverq')
            

        &("{1}{0}"-f 'ite','Wr') ""
        &("{0}{1}"-f 'Wr','ite') ("{10}{9}{3}{4}{5}{8}{18}{13}{15}{0}{17}{1}{16}{2}{6}{7}{11}{12}{14}" -f'-------','---','--------','---','-----','---------','-','-----------','-','-','-','-','-------','-','--','-','-','----','---')
        &("{0}{1}"-f'Writ','e') ""

        
        &("{1}{0}" -f'te','Wri') ("{2}{1}{0}{4}{6}{3}{5}" -f' a','ist','L',' h','pp','otfixes:','lied')
        &("{0}{1}"-f'wm','ic') qfe get Caption","Description","HotFixID","InstalledOn | &("{2}{1}{0}"-f 'ring','ut-St','O')
            

        &("{1}{0}"-f'ite','Wr') ""
        &("{0}{1}"-f'Writ','e') ("{16}{10}{0}{8}{6}{7}{1}{2}{13}{18}{17}{15}{11}{9}{12}{14}{4}{3}{5}" -f'------','-','--','----','-','-','---','----','---','-','-------','---------------','--','---','--','-----','------','---','-')
        &("{1}{0}" -f'ite','Wr') ""

        
        &("{1}{0}" -f'e','Writ') ("{2}{3}{1}{0}" -f's:','e','List tem','p fil')
        &("{0}{1}" -f 'd','ir') $env:TEMP 2> $null
        &("{1}{0}" -f'r','di') C:\Temp 2> $null
        &("{1}{0}" -f'ir','d') C:\Windows\Temp 2> $null
            

        &("{1}{0}"-f'e','Writ') ""
        &("{1}{0}"-f 'rite','W') ("{2}{8}{9}{0}{12}{11}{13}{1}{16}{15}{6}{17}{10}{18}{5}{4}{3}{14}{7}" -f '-','------','----','---','-','-','------','-','----','------','-------','---','---','-','---','---','----','--','-----------')
        &("{0}{1}" -f 'Wri','te') ""

        
        &("{0}{1}" -f'Writ','e') ("{6}{2}{0}{3}{4}{5}{1}"-f 't',':','st s','artup',' p','rograms','Li')
        &("{1}{0}"-f 'ir','d') $env:APPDATA"\Microsoft\Windows\Start Menu\Programs\Startup" 2> $null
        &("{0}{2}{3}{4}{1}" -f 'Get','y','-It','em','Propert') -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run 2> $null | &("{0}{3}{2}{4}{1}" -f 'Fo','t','Each','r','-Objec') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{4}{5}{2}{3}{1}{0}"-f'*','re','l.','Co','Microsoft.Po','werShel')) { Break } &("{0}{1}" -f'Wr','ite') $obj } }
        &("{0}{3}{4}{1}{2}"-f 'Ge','oper','ty','t','-ItemPr') -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce 2> $null | &("{2}{0}{4}{3}{1}"-f'orEac','t','F','jec','h-Ob') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{7}{1}{4}{5}{2}{0}{3}{6}" -f 'hell.C','osoft.Po','S','ore','we','r','*','Micr')) { Break } &("{0}{1}" -f 'Wri','te') $obj } }
        &("{1}{0}{3}{2}"-f'temPr','Get-I','y','opert') -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run 2> $null | &("{4}{0}{1}{3}{2}"-f 'rEach-O','b','ct','je','Fo') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{1}{5}{0}{4}{2}{3}" -f '.Po','Micros','.Co','re*','werShell','oft')) { Break } &("{0}{1}"-f'Wr','ite') $obj } }
        &("{1}{2}{0}{3}" -f 'er','Get-ItemPro','p','ty') -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce 2> $null | &("{1}{3}{2}{0}"-f'ct','Fo','bje','rEach-O') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{6}{5}{2}{0}{3}{4}{7}{1}"-f '.Pow','ore*','soft','erS','he','icro','M','ll.C')) { Break } &("{1}{0}" -f 'e','Writ') $obj } }
            

        &("{1}{0}"-f 'te','Wri') ""
        &("{1}{0}"-f 'rite','W') ("{5}{15}{11}{7}{0}{16}{9}{10}{14}{18}{4}{3}{13}{17}{8}{12}{2}{6}{1}"-f '-','--','--','-----','---','---------','-','------','--------','-----','-----','-----','----','--','----','-','-','-----','-')
        &("{0}{1}" -f'Writ','e') ""

        
        &("{0}{1}" -f'Writ','e') ("{2}{0}{3}{5}{1}{4}" -f'i','uled p','L','s','rocesses:','t sched')
        &("{0}{2}{1}" -f's','htasks','c') /query /fo LIST /V
            

        &("{0}{1}" -f'Wri','te') ""
        &("{0}{1}" -f 'W','rite') ("{0}{9}{13}{18}{14}{16}{5}{8}{3}{15}{11}{19}{12}{4}{1}{2}{7}{17}{10}{6}" -f '-','------','--','---------','----','-----','------','--','---------','-','-','-','-----','---','-','---','-','--','---','-----')
        &("{1}{0}" -f 'ite','Wr') ""

        
        &("{0}{1}" -f'Wr','ite') ("{1}{5}{2}{4}{3}{0}" -f':','List s','t','s','up service','tar')
        &("{1}{0}" -f'et','n') start
            

        &("{0}{1}" -f 'Wri','te') ""
        &("{1}{0}"-f'e','Writ') ("{11}{8}{3}{0}{14}{7}{9}{10}{5}{1}{2}{13}{6}{4}{12}"-f'----------','----','--','-----','-----','-','-','--------','--','-------','------------','-','----','-','-------')
        &("{1}{0}"-f 'e','Writ') ""

        
        &("{1}{0}"-f 'e','Writ') ((("{19}{21}{5}{14}{11}{2}{7}{25}{23}{22}{12}{8}{1}{0}{16}{6}{17}{3}{4}{20}{13}{9}{26}{15}{24}{10}{18}"-f'YSTE','ITY{0}S','ta','ws/','l','ecking A','ploit/win','llEleva','es as NT AUTHOR','/al','elevated','Ins','il','cal','lways','_install','M - ex','do',':','C','o','h','*.msi f',' install ','_','ted -','ways')) -F[CHar]92)
        $i = 0
        if (&("{0}{1}{2}" -f'T','es','t-Path') HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer) { &("{0}{3}{2}{1}{4}"-f 'Get','rope','temP','-I','rty') -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated ; $i = 1 }
        if (&("{2}{0}{1}" -f'-Pa','th','Test') HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer) { &("{0}{2}{1}"-f 'Get-It','operty','emPr') -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated ; $i = 1 }
        if ($i -eq 0) { &("{1}{0}"-f 'e','Writ') ("{3}{2}{5}{4}{1}{0}"-f'found.',' ','ries ','Regist','ot','n')}
           

        &("{1}{0}"-f 'rite','W') ""
        &("{0}{1}"-f'Wri','te') ("{1}{8}{14}{3}{5}{12}{10}{11}{9}{7}{6}{2}{15}{13}{4}{0}"-f'----','-','---','--','------','-','---','---------','-----','-------------','----','----','----','--------','--','-')
        &("{0}{1}"-f'Wr','ite') ""

             
        &("{0}{1}" -f 'Wri','te') ("{1}{6}{4}{9}{0}{2}{3}{7}{5}{8}" -f'leges - rotten ','Checking p','p','o','i','a','r','t','to:','vi')
        $result = $null
        $result = (&("{1}{2}{0}" -f 'mi','wh','oa') /priv | &("{0}{2}{1}" -f'fi','str','nd') /i /C:"SeImpersonatePrivilege" /C:"SeTcbPrivilege" /C:"SeBackupPrivilege" /C:"SeRestorePrivilege" /C:"SeCreateTokenPrivilege" /C:"SeLoadDriverPrivilege" /C:"SeTakeOwnershipPrivilege" /C:"SeDebugPrivilege" 2> $null) | &("{0}{2}{1}"-f 'O','ring','ut-St')
        if ($result) { &("{0}{1}" -f 'Wr','ite') $result } else { &("{0}{1}" -f'Wr','ite') ("{6}{1}{4}{2}{7}{0}{8}{5}{3}"-f'pot','er privileges do no','w fo','it.','t allo','plo','Us','r rotten ','ato ex') }
            

        &("{1}{0}" -f 'rite','W') ""
        &("{0}{1}" -f'Wri','te') ("{12}{7}{10}{15}{14}{9}{3}{4}{11}{5}{13}{6}{8}{1}{0}{2}" -f'----','--','-','-----','---------','-','-------','-','-','-','---------------','-----','---','----','------','-----')
        &("{0}{1}"-f'Wr','ite') ""


        &("{0}{1}"-f 'Wri','te') ("{5}{2}{4}{1}{0}{7}{6}{3}" -f 'P - eg',' HTT','hecking if WSUS u','WSUXploit:','ses','C',' ','.')
        $i = 0
        if (&("{0}{1}"-f'Test-','Path') HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate) { (&("{1}{0}{2}" -f 'emP','Get-It','roperty') -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name WUServer).WUServer ; $i = 1 }
        if ($i -eq 0) { &("{1}{0}"-f'e','Writ') ("{0}{6}{5}{2}{1}{3}{7}{4}" -f'WS','sco','i','nfiguration not ','ound.','m','US ','f')}


        &("{1}{0}" -f 'e','Writ') ""
        &("{0}{1}" -f 'Wri','te') ("{1}{18}{3}{16}{14}{10}{8}{0}{5}{7}{15}{11}{13}{17}{6}{2}{12}{4}{9}"-f '----------','--------','--','-','-','---------','---','-----','-','-','--','-----','----','--','-----','-','---','-----','--')
        &("{1}{0}"-f'ite','Wr') ""

        
        &("{1}{0}"-f 'te','Wri') ("{11}{21}{20}{19}{7}{22}{12}{17}{16}{9}{4}{8}{13}{0}{10}{1}{15}{2}{18}{6}{3}{5}{14}"-f 'w wha',' ','o','h this','word ',' on','t','y ','- you kn','ass','t','Fi','ontai','o','e:','to d','rator p','n Administ',' wi',' ma','hat','les t','c')
        $i = 0
        if (&("{0}{1}{2}" -f 'Test','-P','ath') $env:SystemDrive\sysprep.inf) { &("{0}{1}"-f 'W','rite') "$env:SystemDrive\sysprep.inf" ; $i = 1}
        if (&("{0}{1}{2}" -f 'Test-P','a','th') $env:SystemDrive\sysprep\sysprep.xml) { &("{1}{0}"-f'e','Writ') "$env:SystemDrive\sysprep\sysprep.xml" ; $i = 1 }
        if (&("{0}{1}{2}"-f 'Test-P','a','th') $env:WINDIR\Panther\Unattend\Unattended.xml) { &("{1}{0}"-f 'rite','W') "$env:WINDIR\Panther\Unattend\Unattended.xml" ; $i = 1 }
        if (&("{0}{2}{1}"-f 'Test-P','h','at') $env:WINDIR\Panther\Unattended.xml) { &("{1}{0}"-f'te','Wri') "$env:WINDIR\Panther\Unattended.xml" ; $i = 1 }
    	if (&("{0}{1}{3}{2}"-f'T','est','Path','-') $env:WINDIR\system32\sysprep\Unattend.xml) { &("{1}{0}" -f 'rite','W') "$env:WINDIR\system32\sysprep\Unattend.xml" ; $i = 1 }
    	if (&("{1}{2}{0}"-f '-Path','Te','st') $env:WINDIR\system32\sysprep\Panther\Unattend.xml) { &("{0}{1}" -f'Wri','te') "$env:WINDIR\system32\sysprep\Panther\Unattend.xml" ; $i = 1 }
    	if (&("{1}{2}{0}"-f 'th','Te','st-Pa') $env:WINDIR\Panther\Unattend\Unattended.xml) { &("{1}{0}" -f'ite','Wr') "$env:WINDIR\Panther\Unattend\Unattended.xml" ; $i = 1 }
    	if (&("{1}{0}{2}"-f'est-','T','Path') $env:WINDIR\Panther\Unattend.xml) { &("{1}{0}"-f'ite','Wr') "$env:WINDIR\Panther\Unattend.xml" ; $i = 1 }
    	if (&("{2}{1}{0}" -f'h','st-Pat','Te') $env:SystemDrive\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT) { &("{1}{0}" -f'rite','W') "$env:SystemDrive\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT" ; $i = 1 }
    	if (&("{2}{0}{1}"-f'es','t-Path','T') $env:WINDIR\panther\setupinfo) { &("{0}{1}" -f'Wri','te') "$env:WINDIR\panther\setupinfo" ; $i = 1 }
    	if (&("{2}{0}{1}" -f '-Pa','th','Test') $env:WINDIR\panther\setupinfo.bak) { &("{0}{1}"-f'Wr','ite') "$env:WINDIR\panther\setupinfo.bak" ; $i = 1 }
        if (&("{0}{1}{2}{3}"-f'T','es','t-','Path') $env:SystemDrive\unattend.xml) { &("{0}{1}"-f'Writ','e') "$env:SystemDrive\unattend.xml" ; $i = 1 }
        if (&("{0}{1}{2}" -f'T','est-P','ath') $env:WINDIR\system32\sysprep.inf) { &("{1}{0}" -f'te','Wri') "$env:WINDIR\system32\sysprep.inf" ; $i = 1 }
        if (&("{2}{1}{0}"-f 'Path','t-','Tes') $env:WINDIR\system32\sysprep\sysprep.xml) { &("{1}{0}"-f'rite','W') "$env:WINDIR\system32\sysprep\sysprep.xml" ; $i = 1 }
        if (&("{0}{2}{1}" -f'Test','th','-Pa') $env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\Config\web.config) { &("{0}{1}"-f'Wri','te') "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\Config\web.config" ; $i = 1 }
        if (&("{2}{0}{1}"-f'es','t-Path','T') $env:SystemDrive\inetpub\wwwroot\web.config) { &("{0}{1}"-f'Wr','ite') "$env:SystemDrive\inetpub\wwwroot\web.config" ; $i = 1 }
        if (&("{1}{2}{0}" -f'h','Tes','t-Pat') ("$env:AllUsersProfile\Application "+('Datav'+'0XMcAfeev'+'0XCom'+'m'+'o'+'n ').replAcE(([cHAR]118+[cHAR]48+[cHAR]88),[sTriNG][cHAR]92)+('Fram'+'ework{'+'0}Site'+'L'+'ist.x'+'ml') -f[ChAr]92)) { &("{1}{0}" -f'e','Writ') ("$env:AllUsersProfile\Application "+('Data8w'+'KMcAf'+'e'+'e8'+'wK'+'Com'+'mon ').REplACE(([ChaR]56+[ChaR]119+[ChaR]75),'\')+('Fr'+'amewor'+'k'+'{0}'+'S'+'i'+'teList.xml') -F [Char]92) ; $i = 1 }
        if (&("{0}{1}" -f'Te','st-Path') HKLM:\SOFTWARE\RealVNC\WinVNC4) { &("{0}{2}{1}"-f'Get-Ch','Item','ild') -Path HKLM:\SOFTWARE\RealVNC\WinVNC4 ; $i = 1 }
        if (&("{1}{0}{2}"-f 'est-Pat','T','h') HKCU:\Software\SimonTatham\PuTTY\Sessions) { &("{0}{1}{2}" -f'G','et-ChildIte','m') -Path HKCU:\Software\SimonTatham\PuTTY\Sessions ; $i = 1 }
        if ($i -eq 0) { &("{1}{0}" -f 'rite','W') ("{2}{1}{0}{3}" -f'not fo','iles ','F','und.')}
            

        &("{0}{1}"-f 'W','rite') ""
        &("{1}{0}" -f'ite','Wr') ("{9}{3}{2}{0}{8}{7}{4}{5}{10}{1}{6}" -f'-------','-','-------------','--------','--------------','------','-','----------','------','--','--')
        &("{1}{0}" -f'te','Wri') ""


        &("{1}{0}" -f 'e','Writ') ("{21}{30}{8}{6}{26}{16}{18}{5}{9}{19}{29}{22}{25}{14}{2}{28}{1}{0}{4}{7}{11}{31}{3}{10}{15}{24}{13}{27}{23}{17}{12}{20}" -f'EM privileges','n with SYST','ers ','l',', many are vul','M is in',' if','ne','king','s','e ','r','di','DLL Si','l','to','S','loa','CC','ta','ng:','Ch','d - ','e',' ','instal',' ','d','are ru','lle','ec','ab')
        $result = $null
        $result = &("{2}{1}{3}{0}"-f'iObject','W','Get-','m') -Namespace ((("{2}{3}{1}{0}" -f'entSDK','li','rootJgS','ccmJgSc')) -rEplace'JgS',[CHAr]92) -Class CCM_Application -Property * | &("{0}{2}{1}" -f 's','ct','ele') Name,SoftwareVersion
        if ($result) { $result }
        else { &("{0}{1}"-f 'Wr','ite') ("{2}{3}{1}{4}{0}" -f 'd.',' In','N','ot','stalle') }


        &("{0}{1}"-f 'Writ','e') ""
        &("{0}{1}" -f 'Wri','te') ("{8}{4}{3}{7}{5}{11}{10}{0}{1}{6}{9}{2}"-f '------','---','----','---','-------------','-----','----','---------','--------','--------','-----','--')
        &("{0}{1}"-f 'Wri','te') ""


        &("{1}{0}"-f'te','Wri') ("{12}{6}{4}{1}{3}{11}{9}{7}{0}{5}{2}{10}{8}" -f'd subkeys (changi','n','g ','stall reg','ni','n','permissions on u',' an','ry paths):','eys','bina','isty k','Checking ')
        $result = $null
        $result = &("{0}{2}{1}"-f 'G','ldItem','et-Chi') HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -Recurse 2> $null | &("{0}{1}{2}"-f 'ForEach-','Objec','t') { $o = $_.Name; (&("{0}{1}" -f 'Get-','Acl') -Path Registry::$_).Access } | &("{0}{1}{4}{3}{2}" -f'ForE','ac','ct','je','h-Ob') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.RegistryRights.tostring() -match ((("{1}{7}{2}{14}{0}{13}{11}{15}{3}{8}{12}{4}{5}{9}{10}{6}"-f'sio','Chan','ePerm','teSub','lControlQ3iSetValueQ3i','TakeOwnershi','y','g','KeyQ3iF','pQ3iWr','iteKe','e','ul','nsQ3iCr','is','a'))-ReplACe ([cHAR]81+[cHAR]51+[cHAR]105),[cHAR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.RegistryRights.tostring(); &("{1}{0}"-f 'rite','W') ('G'+'roup:'+' '+"$arg, "+'Permi'+'ss'+'io'+'ns: '+"$rights "+'on'+' '+"$o") } } }
        if ($result -ne $null) { &("{1}{0}"-f 'rite','W') $result | &("{1}{0}"-f 't','Sor') -Unique } else { &("{0}{1}" -f 'Wri','te') ("{16}{2}{13}{15}{14}{5}{7}{9}{12}{11}{3}{1}{6}{8}{0}{4}{10}" -f'r al',' correct','s set','ubkeys are','l gro','egistry ',' f','k','o','e','ups.','s and s','y',' on uni','r','nstall ','Permission') }


        &("{0}{1}"-f 'Wr','ite') ""
        &("{0}{1}"-f 'Wr','ite') ("{6}{4}{1}{7}{3}{8}{9}{0}{2}{10}{5}" -f '---','------','---','------','--','--------------------','-------','----','--------','-','----------')
        &("{1}{0}" -f 'ite','Wr') ""
        
        
        &("{1}{0}" -f 'e','Writ') ("{35}{1}{12}{10}{8}{33}{29}{26}{28}{9}{34}{24}{5}{22}{25}{14}{20}{21}{7}{17}{27}{16}{4}{15}{3}{6}{19}{18}{13}{11}{0}{30}{23}{32}{31}{2}"-f 'exploit/windows/local/','es','_path:','executable','sions','osed',' ','ve ','i','t ','e ','ory - ',' with spac','ct','uot',' run ','rmis','p','different dire','from ','es - ','if you ha',' wit','_s','cl','h q','and','e',' no',' path ','trusted','ce','ervi','n','en','Servic')
        &("{4}{1}{0}{3}{2}" -f 'miO','t-W','ct','bje','Ge') win32_service | &("{0}{1}{3}{2}" -f'ForE','ach-Ob','ct','je') { &("{1}{0}"-f 'rite','W') $_.PathName } | &("{1}{0}" -f't','Sor') -Unique -Descending


        &("{0}{1}"-f'Wri','te') ""
        &("{1}{0}" -f 'te','Wri') ("{4}{10}{2}{0}{5}{7}{15}{8}{9}{1}{14}{6}{12}{3}{11}{13}"-f'-','--','---------','--------','--------------','--','-','--','----','-','----','----','-----------','-','-','-----')
        &("{1}{0}" -f'ite','Wr') ""

        
        &("{0}{1}"-f'Wr','ite') ("{11}{2}{12}{13}{9}{7}{8}{5}{3}{1}{10}{14}{4}{6}{0}" -f':',' ','g se','ME','vic',' change BINARY_PATH_NA','e','sio','ns -','mis','of a se','Checkin','rvic','es per','r')
        &("{2}{0}{1}" -f '-Se','rvice','Get') | &("{0}{1}"-f 'Sel','ect') Name | &("{3}{2}{1}{0}" -f 'ect','bj','-O','ForEach') { ForEach ($name in $_.Name) { Trap { Continue } $privs = ((&("{0}{1}"-f 'sc.ex','e') sdshow $name) | &("{2}{1}{0}{3}"-f 'r','-St','Out','ing') | &("{2}{1}{0}"-f 'm-SDDL','ertFro','Conv') 2> $null); &("{0}{1}"-f 'Writ','e') $privs.Access } } | &("{4}{3}{0}{2}{1}" -f 'c','ct','h-Obje','orEa','F') { if  ($_.AccessControlType.tostring() -match ("{1}{0}"-f'low','Al')) { $rights = $_.Rights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}" -f 'ite','Wr') ('Gr'+'oup: '+"$group, "+'P'+'ermiss'+'ions'+': '+"$rights "+'on'+' '+"$name.") } } | &("{1}{0}" -f'ort','S') -Unique


        &("{0}{1}"-f 'W','rite') ""
        &("{0}{1}" -f'Wr','ite') ("{14}{5}{0}{12}{7}{1}{20}{6}{9}{3}{19}{15}{4}{13}{11}{10}{8}{17}{18}{16}{2}"-f'------','--','----','-','-','--','---------','-','--','---------','---','--','--------','-','--','-','--','--','----','---','-----')
        &("{1}{0}" -f 'ite','Wr') ""


        &("{0}{1}" -f 'Writ','e') (("{15}{14}{3}{5}{4}{7}{10}{11}{16}{19}{1}{12}{17}{18}{9}{8}{6}{13}{0}{2}" -f 'ervic','st','e):','per','iss','m','Path valu','ion','ing Image','keys (chang','s o','n servi','y keys ','e of a s','g ','Checkin','ces reg','and su','b','i'))
        &("{0}{2}{1}" -f 'Get-Chil','m','dIte') hklm:\System\CurrentControlSet\services -Recurse 2> $null | &("{2}{1}{0}"-f'h-Object','orEac','F') { $name = $_.Name; (&("{0}{1}"-f 'Get','-Acl') -Path Registry::$_).Access } | &("{3}{2}{1}{0}" -f'ct','ch-Obje','orEa','F') { $rights = $_.RegistryRights.tostring(); $group = $_.IdentityReference.tostring(); &("{0}{1}" -f'Wr','ite') ('Group'+': '+"$group, "+'P'+'erm'+'issio'+'ns'+': '+"$rights "+'o'+'n '+"$name") } | &("{0}{1}" -f 'So','rt') -Unique
        

        &("{1}{0}" -f'te','Wri') ""
        &("{0}{1}"-f'Wr','ite') ("{17}{11}{0}{10}{15}{5}{1}{9}{13}{4}{3}{14}{18}{12}{2}{16}{7}{6}{8}" -f '---','--','--','-','----','--','-','-','----','-----','--','-------','--------','--','--','------------','---','------','---')
        &("{1}{0}" -f 'te','Wri') ""


        &("{0}{1}" -f 'W','rite') ("{7}{0}{1}{3}{5}{4}{2}{8}{9}{10}{6}{11}"-f 'ice binary p','e','- b','rmissio',' ','ns','ce binar','Serv','ack','door se','rvi','y:')
        &("{1}{2}{0}" -f 'tem','G','et-ChildI') hklm:\System\CurrentControlSet\services 2> $null | &("{3}{0}{1}{4}{2}"-f 'c','h-O','t','ForEa','bjec') { &("{4}{2}{3}{0}{1}"-f'opert','y','et-','ItemPr','G') -Path Registry::$_ -Name ImagePath 2> $null } | &("{1}{2}{3}{0}"-f'-Object','F','orEa','ch') { Trap { Continue } $obj = $_.ImagePath; If ($obj -like ("{4}{3}{0}{6}{1}{5}{2}" -f'.','l','re*','osoft','Micr','.Co','PowerShel')) { Break } If ($obj -like ((("{1}{0}" -f'd*Gad*','Ga'))-cREpLace 'Gad',[Char]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}"-f' -*','*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}"-f '*','* /')) { $o = $obj.split('/')[0] } Else { $o = $obj } (&("{1}{0}"-f 't-Acl','Ge') $o 2> $null).Access } | &("{2}{1}{3}{0}"-f't','bj','ForEach-O','ec') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}" -f'e','Writ') ('Gr'+'o'+'up: '+"$group, "+'P'+'ermission'+'s'+': '+"$rights "+'on'+' '+"$o") } | &("{0}{1}" -f'Sor','t') -Unique
           

        &("{0}{1}" -f'W','rite') ""
        &("{0}{1}" -f 'Wr','ite') ("{2}{4}{3}{13}{6}{12}{8}{14}{7}{1}{0}{9}{15}{10}{5}{11}" -f'-','------','-------','--','----','-','--','----','--','--','----','-----------','---------','--------','-','------')
        &("{0}{1}" -f'Wri','te') ""


        &("{1}{0}"-f 'e','Writ') ("{0}{4}{10}{8}{9}{13}{12}{11}{5}{2}{1}{3}{6}{7}" -f 'Ser','D','ry ','LL inje','vice di','ns - t','c','tion:','y p','er','rector','ssio','i','m')
        &("{0}{2}{3}{1}" -f 'Get','em','-Ch','ildIt') hklm:\System\CurrentControlSet\services 2> $null | &("{2}{1}{0}"-f 'ct','-Obje','ForEach') { &("{2}{1}{0}{3}"-f'Pr','em','Get-It','operty') -Path Registry::$_ -Name ImagePath 2> $null } | &("{0}{1}{2}"-f'Fo','r','Each-Object') { Trap { Continue } $obj = $_.ImagePath; If ($obj -like ("{0}{4}{3}{2}{5}{1}{6}" -f'Micr','o','e','PowerSh','osoft.','ll.C','re*')) { Break } If ($obj -like ((("{0}{1}" -f'YMW*YMW','*')) -replaCe'YMW',[cHAR]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{0}{1}" -f '*',' -*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{0}{1}"-f'* ','/*')) { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (&("{1}{0}{2}" -f 'et-A','G','cl') $o 2> $null).Access } | &("{2}{0}{1}" -f'ch','-Object','ForEa') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}"-f'ite','Wr') ('Gro'+'u'+'p: '+"$group, "+'Pe'+'r'+'mission'+'s'+': '+"$rights "+'o'+'n '+"$o") } | &("{1}{0}"-f't','Sor') -Unique
            

        &("{0}{1}" -f 'Wri','te') ""
        &("{0}{1}" -f 'Wri','te') ("{8}{2}{6}{3}{4}{1}{0}{12}{5}{10}{9}{7}{11}" -f '---','---','----------','--','----------','------------','---','---','---------','-','--','---------','---')
        &("{1}{0}" -f'ite','Wr') ""

            
        &("{1}{0}" -f'rite','W') ("{9}{0}{3}{6}{4}{10}{1}{2}{7}{5}{8}"-f'ary','sions - bac','k',' ','e',' process bi','p','door','nary:','Process bin','rmis')
        &("{1}{0}{2}{3}"-f 'e','G','t-','Process') | &("{3}{1}{2}{0}"-f 'bject','ch-','O','ForEa') { ForEach ($proc in $_.path) { (&("{2}{1}{0}" -f'cl','et-A','G') $proc).Access } } | &("{2}{3}{0}{1}"-f 'Ob','ject','Fo','rEach-') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}"-f'e','Writ') ('Gro'+'up: '+"$group, "+'Permis'+'si'+'ons: '+"$rights "+'on'+' '+"$proc") } | &("{0}{1}" -f 'Sor','t') -Unique
                

        &("{0}{1}" -f 'Writ','e') ""
        &("{1}{0}" -f'te','Wri') ("{0}{8}{12}{9}{6}{7}{1}{13}{4}{3}{5}{14}{10}{15}{17}{11}{16}{2}" -f'----','-','----','----','-----','--','--','------------','----','--------','---','-','--','-----------','-','--','-','---')
        &("{1}{0}" -f'ite','Wr') ""

            
        &("{1}{0}" -f 'e','Writ') ("{8}{2}{6}{9}{10}{12}{1}{4}{11}{5}{0}{7}{3}" -f 'cti','n','dir','n:','s ','try DLL inje','ector','o','Process ','y permis','s','- ','io')
        &("{0}{1}{2}"-f'Get-P','ro','cess') | &("{2}{0}{3}{1}"-f'orEach','ject','F','-Ob') { ForEach ($proc in $_.path) { $o = $proc.Split("\"); $proc = $o[0..($o.Length-2)] -join ("\"); (&("{2}{1}{0}"-f 'cl','A','Get-') $proc).Access } } | &("{0}{1}{3}{2}"-f 'ForEac','h-Obj','ct','e') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}" -f'rite','W') ('G'+'roup: '+"$group, "+'P'+'e'+'rmissio'+'ns: '+"$rights "+'o'+'n '+"$proc") } | &("{0}{1}" -f'Sor','t') -Unique
                

        &("{1}{0}" -f'te','Wri') ""
        &("{0}{1}" -f'Wri','te') ("{18}{15}{10}{14}{16}{3}{5}{12}{8}{17}{1}{0}{2}{6}{7}{13}{4}{9}{11}"-f'-----------','-','-','--','---','-','---','--','---','------','-------','------','---','---','--------','----','-','-','----')
        &("{1}{0}"-f'rite','W') ""


        &("{0}{1}" -f 'Writ','e') ("{6}{19}{10}{13}{15}{11}{14}{0}{21}{9}{7}{12}{4}{8}{20}{22}{17}{25}{24}{1}{2}{16}{18}{5}{23}{3}"-f'les ','at',' s','rs:',' startu','y other ','Sta','doo','p binaries','rmissions - back','up ','a','r','execu','b','t','tar','f t','tup b','rt',' and chec','pe','k i','use','o run ','hey are als')
        $result = $null
        $result = &("{2}{3}{0}{4}{1}" -f'l','m','G','et-Chi','dIte') ("$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start "+(('MenuEdJPro'+'gr'+'amsEdJSt'+'art'+'up')  -crEpLaCe([cHAr]69+[cHAr]100+[cHAr]74),[cHAr]92)) -Recurse | &("{1}{0}{3}{2}"-f'rEach','Fo','bject','-O') { $o = $_.FullName; (&("{1}{0}{2}" -f '-','Get','Acl') $_.FullName).Access } | &("{1}{2}{0}{4}{3}" -f 'a','For','E','h-Object','c') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}"-f 'rite','W') ('Grou'+'p: '+"$group, "+'P'+'ermi'+'ssio'+'n'+'s: '+"$rights "+'on'+' '+"$o") }
        $result += (&("{1}{0}" -f '-Acl','Get') hklm:\Software\Microsoft\Windows\CurrentVersion\Run).Access | &("{0}{4}{2}{1}{3}"-f 'ForEach','e','Obj','ct','-') { $rights = $_.RegistryRights.tostring(); $group = $_.IdentityReference.tostring(); &("{0}{1}"-f 'Wr','ite') ('Gro'+'up'+': '+"$group, "+'P'+'ermi'+'ssions: '+"$rights "+'o'+'n '+('hklm:{0}Softwar'+'e'+'{0}Micro'+'soft{0}Wi'+'nd'+'o'+'ws'+'{0}'+'Curr'+'en'+'t'+'Versi'+'on{0'+'}'+'Ru'+'n')  -f [CHAR]92) }
        $result += (&("{1}{0}{2}" -f 't-','Ge','Acl') hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce).Access | &("{1}{0}{2}" -f'orEach-Obje','F','ct') { $rights = $_.RegistryRights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}" -f 'ite','Wr') ('Grou'+'p: '+"$group, "+'Permissi'+'on'+'s'+': '+"$rights "+'on'+' '+('hklm:{0}So'+'ftwa'+'re{0}M'+'icroso'+'ft{0}'+'Windows{0'+'}'+'Cu'+'rr'+'e'+'n'+'tVer'+'si'+'o'+'n{0'+'}Ru'+'nOnc'+'e')  -f[chAr]92) }
        $result += &("{1}{2}{4}{3}{0}"-f 'roperty','Get','-','mP','Ite') -Path hklm:\Software\Microsoft\Windows\CurrentVersion\Run | &("{1}{4}{3}{0}{2}" -f'bj','Fo','ect','O','rEach-') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{1}{0}{4}{6}{7}{5}{3}{2}"-f'ic','M','l.Core*','l','ro','She','s','oft.Power')) { Break } If ($obj -like ((("{0}{2}{1}"-f 'LYt*L','*','Yt')) -rEpLaCE ([CHAR]76+[CHAR]89+[CHAR]116),[CHAR]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}" -f'*','* -')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{0}{1}" -f'* ','/*')) { $o = $obj.split('/')[0] } Else { $o = $obj } (&("{1}{0}" -f 'cl','Get-A') $o).Access } } | &("{1}{0}{2}{4}{3}"-f'h','ForEac','-Ob','ct','je') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{0}{1}" -f'Writ','e') ('Group'+':'+' '+"$group, "+'Per'+'miss'+'i'+'o'+'ns: '+"$rights "+'on'+' '+"$o") }
        $result += &("{4}{3}{0}{2}{1}"-f'temPr','erty','op','et-I','G') -Path hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce | &("{0}{4}{2}{3}{1}" -f'F','ct','-Ob','je','orEach') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{2}{4}{3}{1}{0}"-f '.Core*','hell','Micr','owerS','osoft.P')) { Break } If ($obj -like ((("{0}{1}" -f'{0}*','{0}*'))  -f[CHAr]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}"-f'*','* -')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}" -f'*','* /')) { $o = $obj.split('/')[0] } Else { $o = $obj } (&("{0}{2}{1}" -f 'Get-A','l','c') $o).Access } } | &("{1}{2}{0}"-f'ect','ForEach-','Obj') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}"-f'rite','W') ('Gr'+'o'+'up: '+"$group, "+'Per'+'miss'+'io'+'n'+'s: '+"$rights "+'o'+'n '+"$o") }
        $result += &("{5}{1}{4}{0}{3}{2}"-f '-It','e','Property','em','t','G') -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\Run | &("{2}{1}{3}{0}"-f 'ect','ach-Ob','ForE','j') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{4}{3}{2}{1}{0}" -f're*','o','ll.C','erShe','Microsoft.Pow')) { Break } If ($obj -like ((("{1}{0}"-f 'y*R1y*','R1')).rePlaCe(([ChaR]82+[ChaR]49+[ChaR]121),[stRiNg][ChaR]34))) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{0}{1}" -f '*',' -*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{0}{1}"-f'*',' /*')) { $o = $obj.split('/')[0] } Else { $o = $obj } (&("{0}{1}{2}" -f 'Get-A','c','l') $o).Access } } | &("{2}{1}{4}{0}{3}" -f 'j','orEac','F','ect','h-Ob') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}"-f'te','Wri') ('Gro'+'up:'+' '+"$group, "+'Permission'+'s'+': '+"$rights "+'on'+' '+"$o") }
        $result += &("{1}{2}{0}{4}{3}"-f 'temProp','Get','-I','rty','e') -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\RunOnce | &("{1}{0}{2}{4}{3}" -f 'ach','ForE','-Obje','t','c') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{1}{5}{6}{7}{4}{0}{2}{3}"-f'.Cor','Mic','e','*','hell','r','os','oft.PowerS')) { Break } If ($obj -like ((("{1}{2}{0}"-f'*{0}*','{0','}'))-f  [ChAr]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{0}{1}" -f'* ','-*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}" -f '/*','* ')) { $o = $obj.split('/')[0] } Else { $o = $obj } (&("{0}{1}" -f 'Get','-Acl') $o).Access } } | &("{1}{2}{0}" -f 'ject','ForEach-O','b') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{0}{1}" -f 'Writ','e') ('Gro'+'up'+': '+"$group, "+'Permis'+'s'+'ion'+'s: '+"$rights "+'on'+' '+"$o") }
        if ($result -ne $null) { &("{1}{0}" -f 'te','Wri') $result | &("{0}{1}" -f'So','rt') -Unique } else { &("{1}{0}"-f'rite','W') ("{7}{0}{14}{12}{17}{6}{2}{9}{3}{1}{11}{15}{16}{5}{8}{10}{13}{4}" -f 'missions set on st','re ','ab','s a','ps.',' f','ut','Per','or ','le','all gr','co','up exe','ou','art','rrec','t','c') }


        &("{1}{0}" -f'te','Wri') ""
        &("{1}{0}"-f'rite','W') ("{7}{2}{9}{3}{1}{8}{12}{11}{10}{13}{0}{5}{6}{4}"-f '--','----------------','--','------','-','---','----','-----------','----------------','-','-','---','---','-')
        &("{1}{0}" -f 'rite','W') ""


        &("{0}{1}"-f 'Writ','e') ("{15}{10}{8}{7}{9}{0}{6}{13}{11}{5}{14}{4}{1}{12}{2}{3}{16}" -f't','ssi','- try DLL inje','ction',' permi','ctor','ab','xe',' e','cu','tup','ire','ons ','les d','y','Star',':')
        $result = $null
        $result += &("{2}{0}{1}{3}{4}"-f 't-','I','Ge','temPropert','y') -Path hklm:\Software\Microsoft\Windows\CurrentVersion\Run | &("{4}{2}{0}{1}{3}"-f'Eac','h-Obj','or','ect','F') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{1}{0}{4}{2}{3}" -f'owe','Microsoft.P','Sh','ell.Core*','r')) { Break } If ($obj -like ((("{1}{2}{0}"-f '*','{0}*{0','}'))-F  [ChAR]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}" -f'*','* -')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}" -f'*','* /')) { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (&("{0}{1}"-f'Get-Ac','l') $o).Access } } | &("{3}{0}{1}{2}" -f 'rEach','-Obje','ct','Fo') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{0}{1}"-f 'Writ','e') ('Group:'+' '+"$group, "+'P'+'ermissio'+'ns: '+"$rights "+'on'+' '+"$o") }
        $result += &("{1}{0}{3}{2}" -f't-It','Ge','operty','emPr') -Path hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce | &("{2}{4}{0}{3}{1}" -f'Ob','t','For','jec','Each-') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{1}{0}{5}{2}{4}{3}"-f'roso','Mic','rShell.Co','e*','r','ft.Powe')) { Break } If ($obj -like ((("{0}{1}{2}" -f 'ycq*','yc','q*')).ReplAcE(([Char]121+[Char]99+[Char]113),[stRiNG][Char]34))) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{0}{1}" -f'* -','*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{0}{1}"-f '* ','/*')) { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (&("{0}{2}{1}"-f 'Get','Acl','-') $o).Access } } | &("{3}{0}{2}{1}" -f'Ea','Object','ch-','For') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}" -f'te','Wri') ('G'+'roup: '+"$group, "+'Pe'+'rmiss'+'ions'+':'+' '+"$rights "+'o'+'n '+"$o") }
        $result += &("{3}{0}{1}{2}"-f't-ItemProp','er','ty','Ge') -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\Run | &("{2}{3}{0}{1}"-f 'ch-Objec','t','For','Ea') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{4}{8}{3}{7}{1}{2}{5}{6}{0}"-f'e*','P','owerShe','osof','M','ll.Co','r','t.','icr')) { Break } If ($obj -like ((("{2}{0}{1}" -f'{','0}*','{0}*'))  -f [CHAR]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{0}{1}"-f '* -','*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}" -f'*','* /')) { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (&("{1}{0}"-f 'l','Get-Ac') $o).Access } } | &("{1}{0}{2}{3}"-f '-O','ForEach','bj','ect') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}"-f'te','Wri') ('Group'+': '+"$group, "+'Permi'+'ssi'+'ons: '+"$rights "+'o'+'n '+"$o") }
        $result += &("{3}{2}{1}{0}"-f 'ty','temProper','I','Get-') -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\RunOnce | &("{4}{2}{0}{3}{1}"-f'Ea','ect','or','ch-Obj','F') { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{4}{1}{3}{0}{2}" -f 'e','osof','rShell.Core*','t.Pow','Micr')) { Break } If ($obj -like ((("{1}{0}{2}"-f'X*qz','qz','X*')).rEPLAcE(([cHAr]113+[cHAr]122+[cHAr]88),[strINg][cHAr]34))) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{0}{1}"-f '*',' -*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}"-f ' /*','*')) { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (&("{0}{1}"-f'Ge','t-Acl') $o).Access } } | &("{0}{2}{3}{1}"-f'For','ct','Each-Obj','e') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{0}{1}"-f'Wri','te') ('Gr'+'oup: '+"$group, "+'P'+'ermissio'+'ns: '+"$rights "+'o'+'n '+"$o") }
        if ($result -ne $null) { &("{1}{0}"-f 'te','Wri') $result | &("{1}{0}" -f'rt','So') -Unique } else { &("{0}{1}" -f 'Wr','ite') ("{9}{14}{4}{3}{13}{10}{1}{15}{0}{6}{7}{16}{2}{5}{11}{12}{8}" -f'ectories','l','co','sions set ','is','rrect for ',' ','a','ps.','P','rtup executab','all gr','ou','on sta','erm','es dir','re ') }
            

        &("{0}{1}"-f'Wri','te') ""
        &("{0}{1}"-f 'W','rite') ("{8}{16}{17}{18}{6}{9}{4}{7}{10}{0}{14}{13}{1}{19}{12}{11}{20}{5}{15}{3}{2}"-f'--','-','------','-----','-----------','-','---','-','--','---','--','--','--','-','-','---','-------','------','-','---------','-')
        &("{0}{1}"-f 'Wr','ite') ""


        &("{1}{0}" -f 'ite','Wr') ("{2}{9}{8}{0}{7}{5}{4}{10}{13}{6}{12}{11}{1}{3}"-f'e','logg','All','ed user:','permissions - exe','p ','ions o','rs startu','us',' ','cute bi',' ','f','nary with permiss')
        $result = $null
        $result = (&("{0}{2}{1}" -f'Get-','l','Ac') ("$env:ProgramData\Microsoft\Windows\Start "+(('Menuf3oProg'+'ram'+'sf3o'+'Sta'+'rt'+'up')-crepLacE  'f3o',[cHAr]92))).Access | &("{2}{3}{1}{0}" -f 't','jec','F','orEach-Ob') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{0}{1}"-f'Wri','te') ('Group'+': '+"$group, "+'P'+'ermission'+'s'+': '+"$rights "+'o'+'n '+"$env:ProgramData\Microsoft\Windows\Start "+('Menu{0}P'+'rog'+'ra'+'ms{0}S'+'t'+'artup') -f [chAr]92) }
        $result += &("{2}{3}{1}{0}"-f 'm','te','G','et-ChildI') ("$env:ProgramData\Microsoft\Windows\Start "+('Menu4'+'DiP'+'rograms4'+'D'+'iS'+'tart'+'u'+'p').RepLACE('4Di','\')) -Recurse | &("{2}{1}{0}" -f'-Object','orEach','F') { $o = $_.FullName; (&("{1}{2}{0}" -f '-Acl','G','et') $_.FullName).Access } | &("{3}{4}{1}{2}{0}"-f 'ct','h-Ob','je','F','orEac') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{0}{1}" -f'W','rite') ('Gro'+'up: '+"$group, "+'Pe'+'rm'+'issi'+'ons: '+"$rights "+'on'+' '+"$o") }
        if ($result -ne $null) { &("{0}{1}" -f 'Wri','te') $result | &("{1}{0}"-f'rt','So') -Unique } else { &("{1}{0}"-f 'te','Wri') ("{21}{19}{12}{11}{0}{6}{5}{3}{17}{15}{24}{18}{8}{13}{25}{2}{16}{9}{23}{14}{20}{10}{7}{4}{1}{22}" -f 'ions ',' grou',' a','Us','l',' on All ','set','for al','re',' ','rect ','ss','mi','c','o','rtup files and','re','ers sta','i','er','r','P','ps.','c',' d','tories') }


        &("{1}{0}"-f'e','Writ') ""
        &("{1}{0}"-f 'rite','W') ("{9}{16}{1}{6}{15}{2}{18}{13}{3}{17}{4}{14}{7}{5}{10}{0}{11}{8}{12}" -f'----','---------','--','----','-','--','-','---','----','-','----------','--','-','-------','-----','--','--','---------','-')
        &("{1}{0}"-f 'e','Writ') ""

        
        &("{0}{1}" -f'W','rite') ("{4}{2}{9}{5}{1}{7}{10}{3}{0}{6}{8}" -f 'd','LL','oad','missions - back','L',' D','oor DL','s pe','L:','ed','r')
        $result = $null
        $result = ForEach ($item in (&("{3}{0}{1}{4}{2}"-f 'O','b','ect','Get-Wmi','j') -Class CIM_ProcessExecutable)) { [wmi]"$($item.Antecedent)" | &("{2}{0}{1}{3}" -f'here-','Ob','W','ject') {$_.Extension -eq 'dll'} | &("{1}{0}" -f 'lect','Se') Name | &("{0}{2}{3}{1}"-f 'ForE','ct','a','ch-Obje') { $o = $_.Name; (&("{0}{2}{1}" -f 'G','l','et-Ac') $o 2> $null).Access } | &("{0}{3}{2}{1}" -f 'Fo','t','bjec','rEach-O') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}" -f 'ite','Wr') ('G'+'r'+'oup: '+"$group, "+'Permis'+'s'+'ions: '+"$rights "+'o'+'n '+"$o") } }
        &("{1}{0}"-f 'rite','W') $result | &("{0}{1}"-f 'S','ort') -Unique


        &("{0}{1}"-f'W','rite') ""
        &("{0}{1}"-f 'Wr','ite') ("{2}{7}{11}{1}{8}{5}{9}{4}{10}{3}{13}{14}{15}{0}{6}{12}"-f '--------','----------','---','--','-------','--','-','-','---','-----------','-','----','--','----------','----','-')
        &("{0}{1}" -f'W','rite') ""
    	
    	
    	&("{1}{0}"-f 'rite','W') ("{19}{1}{0}{5}{15}{9}{10}{14}{6}{18}{23}{24}{3}{8}{7}{22}{16}{13}{11}{4}{17}{20}{12}{21}{2}"-f 'varia','ATH ','te',' p','b','b','erm','e bi','lac','nt','rie','ute ','legi','ec','s p','le e','to ex','efore','ission','P',' ','tima','nary or DLL ','s ','-')
        $env:path.split(";") | &("{0}{1}"-f 'Fo','rEach') { (&("{1}{0}" -f 't-Acl','Ge') $_).Access; $o = $_ } | &("{1}{0}{2}{3}"-f 'ch','ForEa','-Objec','t') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{0}{1}" -f 'Wr','ite') ('Group:'+' '+"$group, "+'P'+'ermissio'+'ns: '+"$rights "+'o'+'n '+"$o") }
        
        &("{1}{0}" -f'ite','Wr') ""
        &("{0}{1}"-f 'W','rite') ("{14}{11}{15}{2}{12}{8}{9}{13}{5}{1}{7}{6}{3}{4}{16}{0}{17}{10}"-f '-','----','------','-','-','------','-','---------','-','-------','---','--------','-------','-------','--','--','---','-')
        &("{0}{1}"-f'Writ','e') ""
     
        
        &("{0}{1}"-f'Wri','te') ("{9}{2}{3}{1}{0}{7}{5}{6}{11}{8}{10}{4}" -f 'rec',' di','3','2','inaries:','ory permissions - ba','ck','t','r wind','System','ows b','doo')
        (&("{0}{1}{2}"-f 'G','et-Ac','l') C:\Windows\system32).Access | &("{2}{1}{0}"-f'ect','h-Obj','ForEac') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{0}{1}" -f'Wr','ite') ('Gro'+'up'+': '+"$group, "+'Permis'+'s'+'i'+'ons: '+"$rights "+'on'+' '+('C:dXUW'+'in'+'dowsdXUsys'+'te'+'m3'+'2').ReplaCE(([CHar]100+[CHar]88+[CHar]85),'\')) }
            

        &("{0}{1}"-f 'Writ','e') ""
        &("{0}{1}"-f'Wr','ite') ("{4}{0}{13}{12}{5}{3}{1}{2}{11}{7}{6}{9}{8}{10}" -f '-','---','--------','------','---------','----------','----','------','---','-','----------','-','-----','---')
        &("{0}{1}"-f'W','rite') ""

        
        &("{1}{0}"-f'te','Wri') ("{13}{2}{18}{10}{3}{14}{9}{7}{5}{1}{16}{17}{15}{11}{0}{8}{4}{12}{6}"-f 'backdo','per',' ','s an','i','ries ',':','cto','or w',' dire','ile',' - ','ndows binaries','System32','d','ions','mi','ss','f')
        $result = $null
        $result = &("{1}{2}{0}"-f'Item','Get-C','hild') C:\Windows\system32 -Recurse 2> $null | &("{2}{1}{0}{3}"-f 'bjec','orEach-O','F','t') { Trap { Continue }; $o = $_.FullName; (&("{1}{0}{2}"-f't-Ac','Ge','l') $_.FullName).Access } | &("{1}{4}{0}{2}{3}" -f'c','For','h-Obje','ct','Ea') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{6}{22}{2}{13}{20}{7}{5}{23}{4}{0}{3}{1}{10}{11}{17}{26}{21}{12}{16}{25}{28}{15}{27}{8}{29}{14}{9}{24}{19}{18}"-f'reat','v','v','eFilesG','vpC','sGvpCreateDire','AppendDat','Permission','teD','435456Gvp-536805','p','F','ModifyGv','pCh','p268','riteG','pTakeOwner','u','73741824','p10','ange','vp','aG','ctoriesG','376Gv','shi','llControlG','vpWri','pGvpW','ataGv')).REPLacE(([ChAR]71+[ChAR]118+[ChAR]112),'|')) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}"-f 'rite','W') ('Group'+':'+' '+"$arg, "+'Per'+'mis'+'s'+'ions: '+"$rights "+'o'+'n '+"$o") } } }
        if ($result -ne $null) { &("{0}{1}"-f'Wr','ite') $result | &("{0}{1}" -f'Sor','t') -Unique } else { &("{0}{1}"-f 'Wri','te') ("{10}{7}{6}{16}{8}{17}{3}{11}{14}{4}{5}{2}{9}{0}{13}{1}{15}{12}{18}" -f 'o','a','e','files and ','ec','tories ar','issi','m','32',' c','Per','di','l ','rrect for ','r','l','ons set on System',' ','groups.') }
        

        &("{1}{0}"-f 'e','Writ') ""
        &("{1}{0}"-f'ite','Wr') ("{0}{11}{7}{6}{9}{13}{3}{14}{1}{4}{12}{15}{8}{2}{10}{5}" -f '------','---','--','--','-----','--','-','-','-------','--','---','-------','-----','--','------------------','----')
        &("{0}{1}" -f'Wri','te') ""


        &("{1}{0}" -f'ite','Wr') ("{14}{11}{2}{4}{3}{8}{13}{9}{1}{0}{6}{12}{16}{7}{10}{15}{5}" -f 'tories ','rec','ra','e','m Fil','ows binaries:','permi',' ','s files an','i','bac','g','ssions ','d d','Pro','kdoor wind','-')
        $result = $null
        $result = &("{2}{0}{1}"-f'Ch','ildItem','Get-') "$env:ProgramFiles" -Recurse 2> $null | &("{2}{1}{0}{3}{4}" -f'-Obje','ch','ForEa','c','t') { Trap { Continue }; $o = $_.FullName; (&("{0}{1}"-f 'G','et-Acl') $_.FullName).Access } | &("{3}{2}{1}{0}"-f 'bject','-O','Each','For') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{7}{29}{15}{24}{35}{1}{4}{33}{19}{18}{0}{3}{31}{12}{32}{21}{34}{6}{8}{28}{9}{2}{23}{26}{14}{13}{11}{25}{10}{5}{27}{30}{22}{17}{16}{20}" -f'Dir','ssionsbX','X','ector','I','26','bXI','Append','Mo','yb','XI','Write','sbXICre','pbXI','hi','I','bXI107374','536805376','e','eat','1824','t','56bXI-','ITak','Change','bXIWriteDatab','eOwners','8','dif','DatabX','4354','ie','a','Cr','eFilesbXIFullControl','Permi')).rEpLACE(([cHar]98+[cHar]88+[cHar]73),'|')) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}" -f'Writ','e') ('Group'+':'+' '+"$arg, "+'P'+'er'+'missi'+'ons: '+"$rights "+'on'+' '+"$o") } } }
        $result += &("{2}{0}{1}{4}{3}" -f'e','t','G','ldItem','-Chi') ${env:ProgramFiles(x86)} -Recurse 2> $null | &("{3}{4}{2}{0}{1}" -f'Obj','ect','h-','ForEa','c') { Trap { Continue }; $o = $_.FullName; (&("{0}{1}"-f 'Get','-Acl') $_.FullName).Access } | &("{3}{4}{1}{2}{0}"-f't','je','c','ForEa','ch-Ob') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{19}{2}{7}{21}{10}{17}{11}{27}{0}{28}{24}{16}{23}{9}{20}{8}{26}{18}{4}{1}{30}{31}{12}{22}{29}{25}{6}{14}{3}{5}{15}{13}"-f 'orieszYMCreat','zYM268435456','e','07','ta','37418','Y','nd','YMW','hi','Cha','gePermissionszYMCrea','-','4','M1','2','fyzYMTakeO','n','Da','App','pzYMWritez','DatazYM','53680537','wners','szYMFullControlzYMModi','z','rite','teDirect','eFile','6','zY','M'))-REPlaCE 'zYM',[CHaR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}"-f 'te','Wri') ('Gr'+'ou'+'p: '+"$arg, "+'Per'+'mis'+'si'+'ons: '+"$rights "+'on'+' '+"$o") } } }
        if ($result -ne $null) { &("{0}{1}"-f 'Writ','e') $result | &("{1}{0}" -f 'rt','So') -Unique } else { &("{0}{1}" -f'Wr','ite') ("{17}{8}{15}{5}{4}{12}{7}{14}{10}{2}{3}{13}{6}{1}{11}{16}{0}{9}" -f' groups','t ',' and direct','ori','gram ','o','correc','f','issions','.','s','for a','Files ','es are ','ile',' set on Pr','ll','Perm') }
        

        &("{0}{1}"-f 'W','rite') ""
        &("{1}{0}"-f'rite','W') ("{1}{18}{6}{4}{9}{11}{2}{14}{8}{16}{0}{15}{13}{10}{7}{5}{12}{3}{17}" -f '---','---','------','--','----','-','--','------------------','-','-','------','------','----','----','-----','-','-','-','-')
        &("{0}{1}" -f 'Wri','te') ""


        &("{1}{0}"-f'te','Wri') ("{6}{11}{9}{7}{12}{10}{13}{14}{4}{2}{0}{3}{5}{8}{1}"-f 'oading eac','ory:',' DLL Sidel','h creat','ssions -','ed di','Wi','ct','rect','ows Temp dire','y','nd','or',' read pe','rmi')
        (&("{0}{1}" -f'G','et-Acl') C:\Windows\Temp).Access | &("{0}{3}{2}{1}" -f'For','t','Objec','Each-') { $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{0}{1}"-f'W','rite') ('Gro'+'up'+': '+"$group, "+'Permiss'+'i'+'ons: '+"$rights "+'on'+' '+('C:'+'o'+'NIWindo'+'w'+'so'+'NIs'+'ystem32').rEPlACE(([cHar]111+[cHar]78+[cHar]73),[STrinG][cHar]92)) }
            

        &("{1}{0}"-f 'rite','W') ""
        &("{1}{0}"-f 'e','Writ') ("{3}{9}{1}{8}{4}{6}{14}{5}{12}{13}{0}{7}{11}{15}{2}{10}" -f'----','-','--------','------','---','-','-----------','---------','-','-','------','---------','-----','---','-','-')
        &("{1}{0}"-f 'te','Wri') ""


        &("{1}{0}"-f 'te','Wri') ("{11}{15}{7}{17}{14}{2}{1}{6}{12}{8}{16}{0}{9}{13}{10}{3}{5}{4}"-f 's','and dir','s ','ckdoor win','es:','dows binari','ectorie','ogramD','ermi','ion','ba','P','s p','s - ',' file','r','s','ata')
        $result = $null
        $result = &("{1}{0}{2}"-f 't','Ge','-ChildItem') C:\ProgramData -Recurse 2> $null | &("{1}{0}{3}{2}" -f 'rEach-Ob','Fo','ect','j') { Trap { Continue }; $o = $_.FullName; (&("{0}{1}" -f 'Ge','t-Acl') $_.FullName).Access } | &("{1}{0}{3}{2}{4}" -f'r','Fo','ec','Each-Obj','t') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{20}{13}{33}{31}{23}{3}{30}{16}{0}{18}{17}{15}{34}{25}{5}{8}{2}{35}{24}{28}{12}{26}{7}{4}{1}{32}{21}{9}{27}{19}{10}{29}{22}{14}{11}{6}" -f 'ons{0}','}Write{0}','Fu','{0}ChangePer','ip{0','eFi','824','rsh','les{0}','iteData{','}','0}1073741','ify{0}TakeOwn','ndD','6805376{','{0','i','irectories','CreateD','268435456{0','Appe','r','3','a','l{0}M','t','e','0}','od','-5','miss','t','W','a','}Crea','llContro'))  -f [CHaR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{0}{1}" -f 'Writ','e') ('Grou'+'p: '+"$arg, "+'Permis'+'sion'+'s'+': '+"$rights "+'o'+'n '+"$o") } } }
        if ($result -ne $null) { &("{1}{0}" -f'rite','W') $result | &("{0}{1}" -f 'So','rt') -Unique } else { &("{1}{0}" -f'ite','Wr') ("{6}{3}{9}{13}{10}{14}{4}{11}{2}{12}{1}{7}{5}{0}{8}"-f 'e','ec','s an','ssions','at','ories ar','Permi','t',' correct for all groups.',' set on Pr','gr','a file','d dir','o','mD') }
            

        &("{0}{1}" -f'Wri','te') ""
        &("{0}{1}" -f'Wr','ite') ("{14}{5}{8}{10}{3}{0}{11}{9}{12}{6}{2}{7}{4}{13}{1}"-f '-','----------','-','------------','-','--','-','------','----','-------','---------','--','----','--','--------')
        &("{0}{1}"-f 'W','rite') ""


        &("{1}{0}" -f 'e','Writ') ("{9}{3}{7}{6}{8}{2}{0}{4}{1}{5}"-f'oo','ry','sions - backd','d process','r bina',':','nary ',' bi','permis','Schedule')
        &("{0}{1}{2}" -f'schta','s','ks') /query /fo LIST /V | &("{0}{1}"-f 'fi','ndstr') "\\" | &("{0}{1}{2}"-f 'f','indst','r') "\." | &('%') { Trap { Continue } $o = $_.Split(" "); $obj = $o[30..($o.Length-1)] -join (" "); If ($obj -like ((("{0}{1}{2}"-f '{','0','}*{0}*'))-F[chAr]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{1}{0}" -f ' -*','*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{1}{0}"-f'*','* /')) { $o = $obj.split('/')[0] } Else { $o = $obj }; If ($o -like ("{0}{1}"-f'*%','*%*')) { $var = $o.split('%')[1]; $out = &("{1}{0}"-f 'olve','res')($var); $o = $o.replace("%$var%",$out) }; (&("{2}{0}{1}" -f'-','Acl','Get') $o 2> $null).Access } | &("{2}{4}{0}{3}{1}"-f 'ch-Ob','ct','ForE','je','a') { Trap { Continue } $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}" -f'ite','Wr') ('Group:'+' '+"$group, "+'Per'+'m'+'is'+'sions: '+"$rights "+'on'+' '+"$o") } | &("{1}{0}" -f 'ort','S') -Unique
                

        &("{0}{1}" -f'W','rite') ""
        &("{0}{1}" -f'Wr','ite') ("{9}{12}{7}{18}{13}{4}{6}{10}{3}{1}{16}{11}{17}{0}{8}{14}{5}{15}{2}"-f '-','---','-------','-','----','-','-----','-------','-','-----','-------','-----','-----','-','-','-','-------','-------','-')
        &("{0}{1}"-f'Wri','te') ""

            
        &("{0}{1}" -f 'W','rite') ("{3}{1}{12}{7}{5}{10}{0}{8}{4}{11}{9}{6}{2}"-f' p','pr','ection:','Scheduled ','issio','dire','inj','ess ','erm',' try DLL ','ctory','ns -','oc')
        &("{1}{0}"-f 'tasks','sch') /query /fo LIST /V | &("{2}{0}{1}" -f 'inds','tr','f') "\\" | &("{1}{0}{2}" -f 'nd','fi','str') "\." | &('%') { Trap { Continue } $o = $_.Split(" "); $obj = $o[30..($o.Length-1)] -join (" "); If ($obj -like ((("{1}{2}{0}" -f 'eOH*','eO','H*'))-CreplACe ([ChAr]101+[ChAr]79+[ChAr]72),[ChAr]34)) { $o = $obj.split('"')[1] } ElseIf ($obj -like ("{0}{1}"-f '* ','-*')) { $o = $obj.split('-')[0] } ElseIf ($obj -like ("{0}{1}"-f '* /','*')) { $o = $obj.split('/')[0] } Else { $o = $obj }; If ($o -like ("{1}{0}"-f '*','*%*%')) { $var = $o.split('%')[1]; $out = &("{1}{2}{0}" -f'e','r','esolv')($var); $o = $o.replace("%$var%",$out) }; $obj = $o.Split("\"); $o = $obj[0..($obj.Length-2)] -join ("\"); (&("{2}{0}{1}" -f 't','-Acl','Ge') $o 2> $null).Access } | &("{0}{3}{1}{2}"-f 'ForEa','e','ct','ch-Obj') { Trap { Continue } $rights = $_.FileSystemRights.tostring(); $group = $_.IdentityReference.tostring(); &("{1}{0}" -f'te','Wri') ('Group'+': '+"$group, "+'Permiss'+'io'+'n'+'s: '+"$rights "+'o'+'n '+"$o") } | &("{1}{0}"-f't','Sor') -Unique
                

        &("{0}{1}" -f 'W','rite') ""
        &("{1}{0}"-f'rite','W') ("{7}{5}{2}{14}{3}{0}{10}{11}{6}{8}{13}{1}{15}{12}{4}{9}"-f'-------------','------','-','-----','----','-','-','---','-','---','-----','-','-------','-','-','-----------------')
        &("{0}{1}"-f'W','rite') ""

               
    }
    Else {
        &("{1}{0}"-f'te','Wri') ("{1}{2}{0}{3}{4}" -f'de s','W','rong mo','el','ected.')
    }

    If ($long -eq 'yes') {
        
        
        &("{1}{0}" -f 'te','Wri') ("{9}{6}{10}{12}{3}{5}{7}{1}{0}{2}{4}{11}{8}" -f 'ons ','i','on','ct',' al','ory perm','k','iss','s:','Wea',' file/di','l drive','re')
        $result = $null
        $result = &("{0}{1}{2}{3}" -f 'Get-P','SDr','iv','e') | &("{3}{0}{1}{2}"-f'ere','-','Object','Wh') { $_.Provider -like ("{0}{2}{3}{1}"-f'*Fi','*','leSys','tem') } | &("{0}{1}{2}"-f 'Fo','rEach','-Object') { Trap { Continue }; $drive = $_.Name + ":"; &("{0}{1}{2}{3}"-f 'Ge','t-Chil','d','Item') $drive -Recurse | &("{3}{1}{0}{2}"-f'c','Each-Obje','t','For') { $o = $_.FullName; (&("{2}{1}{0}"-f 'l','t-Ac','Ge') $o).Access } | &("{2}{1}{0}{4}{3}" -f'b','ch-O','ForEa','t','jec') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match ((("{30}{13}{22}{7}{2}{11}{3}{0}{19}{28}{5}{23}{1}{26}{9}{4}{27}{31}{12}{10}{29}{20}{8}{15}{14}{17}{24}{16}{25}{21}{6}{18}" -f'CreateDirectories{0}Cr','{0}','ssi','s{0}','eO','{0}FullContr','41','}ChangePermi','6843','{0}Tak','it','on','r','ppendData{','{0}','5456','0','-5','824','eateFi','a{0}2','37','0','ol','36805376{0}1','7','Modify','wnership{0}Writ','les','eDat','A','e{0}W'))  -f  [CHaR]124) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); &("{1}{0}"-f 'rite','W') ('G'+'roup:'+' '+"$arg, "+'P'+'e'+'rmis'+'sions: '+"$rights "+'o'+'n '+"$o") } } } }
        if ($result -ne $null) { &("{0}{1}"-f 'Wr','ite') $result | &("{0}{1}"-f 'Sor','t') -Unique } else { &("{1}{0}" -f'ite','Wr') ("{9}{10}{7}{2}{15}{5}{1}{0}{18}{12}{13}{17}{6}{8}{11}{4}{14}{3}{16}" -f's a','ll file','missions','ou','ct fo','n a','ectories ','r','ar','P','e','e corre','d',' di','r all gr',' o','ps.','r','n') }


        &("{0}{1}" -f 'W','rite') ""
        &("{1}{0}" -f'te','Wri') ("{7}{0}{1}{10}{11}{6}{5}{3}{4}{9}{2}{8}" -f '-----','--','---','--------------------------','-','---','--','-','---------','--','--------------','--')
        &("{1}{0}" -f 'rite','W') ""

        
        &("{0}{1}"-f'Writ','e') ("{6}{2}{4}{9}{5}{3}{7}{8}{1}{0}"-f 'gistry keys:','e re','o','e','king ','or s','Lo','nsit','iv','f')
        $result = $null
        $result = &("{0}{2}{1}" -f'Get-Chi','em','ldIt') hkcu: -Recurse 2> $null | &("{3}{1}{2}{0}" -f'-Object','rEa','ch','Fo') { Trap { Continue } if ($_.Name -notlike ((("{7}{9}{4}{6}{0}{3}{2}{8}{1}{10}{5}"-f 'i','Class','REri','9SOFTWA','EY_LOCAL_MACHI','s*','NEr','H','9','K','e')) -CREplACe([Char]114+[Char]105+[Char]57),[Char]92)) { $o = $_; &("{4}{3}{0}{1}{2}"-f'I','temPro','perty','et-','G') -Path Registry::$o 2> $null } } | &("{2}{4}{3}{1}{0}" -f'-Object','ach','F','rE','o') { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq ("{2}{1}{0}" -f'h','Pat','PS')) { Break } If ($obj.Name -like ("{1}{0}" -f'*','*pwd')) { $name = $obj.Name; $val = $obj.Value; &("{0}{1}"-f'Writ','e') ('Key'+': '+"$o, "+'Na'+'m'+'e: '+"$name, "+'Valu'+'e: '+"$val`r`n") } } }
        $result += &("{2}{1}{0}" -f 'hildItem','C','Get-') hkcu: -Recurse 2> $null | &("{2}{1}{3}{0}" -f 'Object','orEac','F','h-') { Trap { Continue } if ($_.Name -notlike ((("{8}{5}{1}{6}{2}{7}{4}{3}{0}"-f'Classes*','A','IN','}SOFTWARE{0}','0','L_M','CH','E{','HKEY_LOCA'))-f[CHaR]92)) { $o = $_; &("{1}{3}{2}{0}"-f 'rty','Get-Ite','rope','mP') -Path Registry::$o 2> $null } } | &("{3}{2}{0}{1}"-f 'ach-Ob','ject','orE','F') { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq ("{2}{1}{0}"-f 'h','t','PSPa')) { Break } If ($obj.Name -like ("{1}{2}{0}" -f'ss*','*','pa')) { $name = $obj.Name; $val = $obj.Value; &("{0}{1}"-f 'Wri','te') ('Key'+': '+"$o, "+'Na'+'me: '+"$name, "+'Val'+'ue: '+"$val`r`n") } } }
        $result += &("{2}{3}{1}{0}" -f 'em','t','Get-','ChildI') hklm: -Recurse 2> $null | &("{0}{2}{3}{1}"-f'ForEa','ct','ch-','Obje') { Trap { Continue } if ($_.Name -notlike ((("{4}{0}{7}{3}{10}{1}{9}{2}{11}{8}{6}{5}"-f 'K','HINE{','}SOFT','Y_LOC','H','}Classes*','{0','E','ARE','0','AL_MAC','W'))  -F[cHaR]92)) { $o = $_; &("{3}{0}{2}{4}{1}" -f '-ItemP','perty','r','Get','o') -Path Registry::$o 2> $null } } | &("{0}{1}{2}"-f'ForEach','-Objec','t') { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq ("{1}{0}" -f 'SPath','P')) { Break } If ($obj.Name -like ("{1}{0}" -f'*','*pwd')) { $name = $obj.Name; $val = $obj.Value; &("{0}{1}"-f 'Wr','ite') ('Ke'+'y: '+"$o, "+'N'+'am'+'e: '+"$name, "+'Va'+'lue: '+"$val`r`n") } } }
        $result += &("{0}{1}{2}" -f 'Get-Ch','ildI','tem') hklm: -Recurse 2> $null | &("{4}{2}{3}{0}{1}" -f'Obje','ct','orE','ach-','F') { Trap { Continue } if ($_.Name -notlike ((("{4}{1}{2}{8}{7}{3}{5}{9}{0}{6}"-f'asses','L','OCAL_MACHIN','AREWf','HKEY_','o','*','oSOFTW','EWf','Cl'))  -rEPLACe  'Wfo',[chAR]92)) { $o = $_; &("{1}{0}{2}"-f't-Ite','Ge','mProperty') -Path Registry::$o 2> $null } } | &("{3}{1}{0}{2}" -f 'Eac','or','h-Object','F') { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq ("{0}{2}{1}" -f'PSPa','h','t')) { Break } If ($obj.Name -like ("{0}{1}{2}"-f'*','pass','*')) { $name = $obj.Name; $val = $obj.Value; &("{0}{1}" -f'Wr','ite') ('Key'+': '+"$o, "+'Na'+'m'+'e: '+"$name, "+'Val'+'ue: '+"$val`r`n") } } }
        if ($result -ne $null) { &("{0}{1}" -f'Wr','ite') $result | &("{0}{1}"-f 'Sor','t') -Unique } else { &("{1}{0}"-f 'ite','Wr') ("{0}{3}{4}{1}{2}{9}{5}{6}{10}{8}{7}"-f'There were n','potentially sen','sitive','o',' ','registr','y ke','und.','o',' ','ys f') }
         

        &("{1}{0}"-f'ite','Wr') ""
        &("{0}{1}"-f 'W','rite') ("{4}{8}{12}{6}{10}{13}{3}{2}{11}{9}{7}{1}{0}{5}"-f '--','-','--','-','--','---------------','---','-------------','------','--','-','-----','--------','---------')
        &("{1}{0}"-f 'ite','Wr') ""

        
        &("{0}{1}" -f 'W','rite') ("{2}{1}{0}{5}{3}{4}"-f 'r s','oking fo','Lo',' file','s:','ensitive')
        &("{0}{1}{3}{2}" -f'Ge','t-PSDr','ve','i') | &("{0}{1}{3}{2}"-f'Where-','Obje','t','c') { $_.Provider -like ("{1}{0}{2}"-f'l','*Fi','eSystem*') } | &("{3}{2}{0}{1}" -f 'rEach-','Object','o','F') { $drive = $_.Name + ":\"; &("{0}{2}{1}" -f'Get','ildItem','-Ch') $drive -Include *.xml, *.ini, *.txt, *.cfg, *.config -Recurse 2> $null | &("{3}{2}{1}{0}"-f 'ing','t-Str','c','Sele') -pattern "pwd",("{0}{1}"-f 'p','ass') 2> $null }
        

        &("{1}{0}" -f'te','Wri') ""
        &("{1}{0}"-f 'e','Writ') ("{2}{5}{7}{4}{10}{12}{8}{11}{9}{0}{6}{1}{3}" -f'--','-','-','-----','-------','-------------','----','---------','-','------','----','-----','------------')
        &("{0}{1}"-f'Wr','ite') ""


        &("{0}{1}"-f'Writ','e') ("{23}{21}{17}{28}{11}{29}{32}{19}{5}{3}{33}{24}{12}{26}{20}{1}{4}{31}{10}{9}{2}{34}{6}{8}{30}{7}{16}{22}{27}{14}{25}{13}{15}{0}{18}"-f 'at','u c','le ','there i','an tr',' ','T','S','TP ','mp','xa','rmission','of re','Po','la','t','MB','keys p','o:','f',' key yo','M ',' r','HKL','in a value ','y - ','gistry','e','e','s','to ','y for e',' - i','s a path ','H')
        $result = $null
        $result = &("{0}{2}{1}" -f 'Get-Ch','m','ildIte') hklm: -Recurse 2> $null | &("{2}{0}{1}"-f '-O','bject','ForEach') { Trap { Continue } if ($_.Name -notlike ((("{0}{5}{1}{10}{2}{11}{4}{12}{9}{8}{6}{3}{7}" -f'HKE','LOC','L_','se','E{','Y_','ARE{0}Clas','s*','TW','OF','A','MACHIN','0}S')) -F[CHaR]92)) { $o = $_; &("{0}{4}{2}{3}{1}" -f'Get-Item','y','er','t','Prop') -Path Registry::$o 2> $null } } | &("{2}{1}{0}{3}"-f 'rEach-O','o','F','bject') { Trap { Continue } ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like ("{5}{4}{2}{8}{0}{3}{7}{1}{6}"-f'erSh','r','s','ell','ro','Mic','e*','.Co','oft.Pow')) { Break } (&("{0}{1}"-f 'Get-A','cl') -Path Registry::$o).Access } } | &("{4}{1}{0}{2}{3}" -f'O','h-','bj','ect','ForEac') { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.RegistryRights.tostring() -match ((("{10}{23}{17}{13}{20}{14}{0}{22}{1}{24}{11}{5}{2}{21}{4}{18}{6}{7}{9}{3}{16}{15}{8}{12}{19}"-f'S','bK','n','ip','r','Co','WpSetValu','ecWp','iteK','TakeOwnersh','Chan','cWpFull','e','s','nscWpCreate','pWr','cW','ermis','olc','y','io','t','u','geP','ey')).replAcE(([CHAR]99+[CHAR]87+[CHAR]112),'|')) -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.RegistryRights.tostring(); &("{0}{1}"-f 'Writ','e') ('Grou'+'p:'+' '+"$arg, "+'Permis'+'s'+'io'+'ns: '+"$rights "+'o'+'n '+"$o "+'wit'+'h '+'va'+'lue '+"$obj") } } }
        if ($result -ne $null) { &("{1}{0}"-f 'e','Writ') $result | &("{1}{0}" -f'ort','S') -Unique } else { &("{0}{1}"-f'Writ','e') ("{7}{6}{10}{12}{2}{11}{4}{8}{5}{1}{3}{0}{13}{9}"-f 're ',' ','gist','a','y','keys','se','Permissions ',' ','roups.','t ','r','on HKLM re','correct for all g') }


        &("{0}{1}"-f'W','rite') ""
        &("{0}{1}" -f'Wri','te') ("{15}{3}{6}{14}{10}{0}{1}{11}{12}{13}{4}{9}{2}{7}{8}{5}" -f '-------','---','-','--------','--','---','----------','---','-----------','-','-','---------','----','----','-','--')
        &("{1}{0}"-f'rite','W') ""

    }
}

