#!/usr/bin/bash
programName=${0##*/}
debug=1
downloadDryRun=0
restartService=1
snortFileName=snortrules-snapshot-29120.tar.gz
rulesTar=https://www.snort.org/rules/$snortFileName
rulesTar="$rulesTar https://www.snort.org/downloads/community/community-rules.tar.gz"
rulesTar="$rulesTar https://rules.emergingthreats.net/open-nogpl/suricata-4.0/emerging.rules.tar.gz"
oinkcode=yourCodeHERE
workDir=/var/tmp/suricata
downloadDir=$workDir/download
archivedDir=$workDir/archive
rulesDir=$workDir/rules
#suricataConfigDir=$workDir/dest
suricataConfigDir=/etc/suricata
#destDir=$workDir/dest
destDir=$suricataConfigDir/rules
#ruleFilesYaml=$workDir/rule-files.yaml
ruleFilesYaml=$suricataConfigDir/rule-files.yaml
checksumSuffix=.sha256sum
curl="/usr/bin/curl --silent --insecure --location"
[[ $debug -eq 1 ]] && curl="$curl -v"
prefix=.
modifyRulesScript=$prefix/updateSuricataRules.pl
disabledRulesList=$prefix/disabledRuleFiles.txt
udpOnlyRuleList=$prefix/udpOnlyRules.txt
disabledProtocolList=$prefix/disabledProtocols.txt
sidBlacklist=$prefix/sid-blacklist.txt
dateSuffix=`/usr/bin/date +%Y-%m-%dT%H%M%S`

function download() {
	url=$1
	outputFile=$downloadDir/${url##*/}
# add oinkcode if snort registred rules
	[[ $url =~ ^https://www\.snort\.org/rules/ ]] && url="$url?oinkcode=$oinkcode"
	[[ $debug -eq 1 ]] && echo "$programName: DEBUG: Downloading $url ..."
	[[ $downloadDryRun -eq 0 ]] && $curl -o $outputFile $url 
	if [[ -f $outputFile ]]; then
		/usr/bin/sha256sum $outputFile > $outputFile$checksumSuffix
		return 0
	else
		echo "$programName: ERROR: Download the rule file FAILED; url=$url"
		return 1
	fi
}

[[ $debug -eq 1 ]] && echo "$programName: DEBUG: START"
[[ -d $workDir ]] || mkdir -p $workDir
cd $workDir

# download
[[ -d $downloadDir ]] || mkdir -p $downloadDir
updatedRulesTarFiles=""
for url in $rulesTar; do
	rulesTarFileName=${url##*/}
	download $url
	if [[ $? -eq 0 ]]; then
		oldHashFile=$archivedDir/$rulesTarFileName$checksumSuffix
		if [[ ! -f $oldHashFile ]]; then
			updatedRulesTarFiles="$updatedRulesTarFiles $rulesTarFileName"
		else
			oldFileHash=`cut -f 1 -d " " $oldHashFile`
			hashFile=$downloadDir/$rulesTarFileName$checksumSuffix
			[[ -f $hashFile ]] && fileHash=`cut -f 1 -d " " $hashFile`
			if [[ "X${oldHashFile:-0000000000000000000000000000000000000000000000000000000000000000}" = "X${fileHash:-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff}" ]]; then
				[[ $debug -eq 1 ]] && echo "$programName: DEBUG: $fileHash $rulesTarFileName"
			else
				[[ $debug -eq 1 ]] && echo "$programName: DEBUG: $fileHash $rulesTarFileName oldFileHash = $oldHashFile"
				updatedRulesTarFiles="$updatedRulesTarFiles $rulesTarFileName"
			fi
		fi
	fi
done

# exit if no updates
if [[ "X$updatedRulesTarFiles" = X ]]; then
	[[ $debug -eq 1 ]] && echo "$programName: DEBUG: No updates available; exit"
	exit 0
fi

# clean rules dir
if [[ -d $rulesDir ]]; then
	[[ "X$rulesDir" = "X/" ]] || rm -rf $rulesDir/*
else
	mkdir -p $rulesDir
fi

# untar
cd $rulesDir
for tarFile in $updatedRulesTarFiles; do
	if [[ -f $downloadDir/$tarFile ]]; then
		[[ $debug -eq 1 ]] && echo "$programName: DEBUG: Untar $tarFile"
		/usr/bin/tar zxf $downloadDir/$tarFile
	fi
done
[[ -d $rulesDir/community-rules ]] && mv $rulesDir/community-rules/*.rules $rulesDir/
[[ -d $rulesDir/rules ]] && mv $rulesDir/rules/*.rules $rulesDir/

# copy Suricata default rules
for rule in `rpm -ql suricata | egrep '^/etc/suricata/rules/.+\.rules'`; do
	[[ -f $rule ]] && cp -p $rule $rulesDir/
done

# backup old rules
[[ -d $archivedDir ]] || mkdir -p $archivedDir
if [[ ! -d $destDir ]]; then
	mkdir -p $destDir
else
	/usr/bin/tar Jcf $archivedDir/oldRules-$dateSuffix.tar.xz $destDir
	[[ $? -eq 0 ]] && rm -f $destDir/*.rules
fi

# disable some rules
# diable tcp rules and enable only udp ones
# disable blacklisted rules by sid
if [[ ! -f $modifyRulesScript ]]; then
	echo "$programName: ERROR: $modifyRulesScript is not found; copy all rules"
	cp -p $rulesDir/*.rules $destDir/
else
	for rule in $rulesDir/*.rules; do
		[[ $debug -eq 1 ]] && echo "$programName: DEBUG: $rule: Modify"
		/usr/bin/perl /root/bin/updateSuricataRules.pl $disabledRulesList $udpOnlyRuleList $disabledProtocolList $sidBlacklist $rule $destDir
	done
fi

# backup old .yaml
[[ -f $ruleFilesYaml ]] && /usr/bin/xz -c $ruleFilesYaml > $archivedDir/${ruleFilesYaml##*/}-$dateSuffix.xz

# write .yaml
cat <<EOF > $ruleFilesYaml
%YAML 1.1
---
rule-files:
EOF
# exclude *.rules files witout any rule definition
for rule in $destDir/*.rules; do
	line=`grep -E -c '^alert\s+' $rule`
	if [[ $line -eq 0 ]]; then
		[[ $debug -eq 1 ]] && echo "$programName: DEBUG: $rule: Empty definition; skip"
	else
		[[ $debug -eq 1 ]] && echo "$programName: DEBUG: $rule: rule count = $line"
		echo " - ${rule##*/}" >> $ruleFilesYaml
	fi
done

chown -R suricata.root $destDir $ruleFilesYaml
[[ $debug -eq 0 ]] && restorecon -R $destDir $ruleFilesYaml

# rename old tar archives and hash files
for tarFile in $updatedRulesTarFiles; do
	oldTarFile=$archivedDir/$tarFile
	oldHashFile=$oldTarFile$checksumSuffix
	newTarFile=$downloadDir/$tarFile
	if [[ -f $oldTarFile ]]; then
		oldFileHash=""
		[[ -f $oldHashFile ]] && oldFileHash=`cut -f 1 -d " " $oldHashFile`
		[[ "X$oldFileHash" = X ]] && oldFileHash=$dateSuffix
		mv $oldTarFile $oldTarFile.$oldFileHash
		[[ -f $oldHashFile ]] && rm -f $oldHashFile
		[[ $debug -eq 1 ]] && echo "$programName: DEBUG: $oldTarFile => $oldTarFile.$oldFileHash"
	fi
	if [[ -f $newTarFile ]]; then
		newHashFile=$newTarFile$checksumSuffix
		[[ -f $newHashFile ]] && mv $newHashFile $oldHashFile
		[[ $debug -eq 1 ]] && echo "$programName: DEBUG: $newHashFile => $oldHashFile"
		mv $newTarFile $oldTarFile
		[[ $debug -eq 1 ]] && echo "$programName: DEBUG: $newTarFile => $oldTarFile"
	fi
done

# restart suricata
if [[ $restartService -eq 1 ]]; then
	[[ $debug -eq 1 ]] && /usr/bin/systemctl status suricata.service
	/usr/bin/systemctl restart suricata.service
	[[ $debug -eq 1 ]] && /usr/bin/systemctl status suricata.service
fi

exit 0
