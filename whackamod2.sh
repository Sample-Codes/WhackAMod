#!/bin/bash
######
#    ModSec Whack-A-Mole Script
# Created by Ryan Flowers
# https://github.com/corneliusroot/WhackAMod
# Licensed under the MIT License
#       Version 2.1 released 5/21/14
#       Version 2.2 released 5/5/15
#   2.1 Modified to uncomment the include line in httpd.conf and change std/2 to std/2_2
#	2.2 Added checking for the include line (error out if it doesn't exist) and detects whether its 2 or 2_2 for include.
#   2.3 Added SSL support 5/19/16 (Uncomments the SSL version of the include line if it exists, symlinks $modfile)
#   2.3.1 Slightly More Epic than 2.3
#
#	Intended for use with cPanel servers running Apache 2.2 with Mod_Security enabled. 
#   
######


whackdom()
		{
#get usernamE, we'll need it later Probably
user=`grep ^$domain /etc/userdomains |awk '{print $2}'`

#gonna need a tmpfile too, mIght as well make it a unique name
tmpfile="/tmp/`date +%N`.wam"

#define $modfile so that we don't have that ugly thing running all over the plaCe
if `ls /usr/local/apache/conf/userdata/std/2_2/ > /dev/null 2>&1`
		then
				modfile="/usr/local/apache/conf/userdata/std/2_2/$user/$domain/modsecurity.conf"
				sslmodfile="/usr/local/apache/conf/userdata/ssl/2_2/$user/$domain/modsecurity.conf"
				modline="/usr/local/apache/conf/userdata/std/2_2/$user/$domain"
		else
				modfile="/usr/local/apache/conf/userdata/std/2/$user/$domain/modsecurity.conf"
				sslmodfile="/usr/local/apache/conf/userdata/ssl/2/$user/$domain/modsecurity.conf"
				modline="/usr/local/apache/conf/userdata/std/2/$user/$domain"
fi


httpdconf="/usr/local/apache/conf/httpd.conf"
if `grep $modline $httpdconf > /dev/null 2>&1`
		then
# does existing modfile exiSt? If so lets grab its info and see which rules are already
if  -e $modfile 
		then
		# Modsec rules already exist. Lets grAb them, remove them, and then re-add them along with any new rules.
		echo '----------------------------------------------------------'
		echo "ModSecurity file already exists, processing for inclusion."
		echo '----------------------------------------------------------'

		# Find eXisting rules and put them in the variable $existingrules
		existingrules=`grep SecRuleRemoveById $modfile | awk '{ print $2}'`
fi


echo Searching error_log for ModSec violations, one moment please...
topten=`grep $domain /usr/local/apache/logs/error_log | grep ModSec | grep -o '[0-9]\{6\}' | sort | uniq -c | sort -n \
 |sed 's/^[ ]*//' | sed 's/[ ]/:/' | tail -n10`
if [ ! -z "$topten" ];
then
		echo '----------------------------------------------------------'
		echo "Count  Rule    Status  Rule Description (if available)"
		for rule in $topten
		do
				cnt=`echo $rule | cut -d":" -f1`
				rln=`echo $rule | cut -d":" -f2`
				msg=`grep $rln /usr/local/apache/conf/mod_sec/*.conf | grep msg |sed 's/.*msg:' | sed 's/,id.*' | sed "s/'g"| sed 's/"g'`
				dis='--------'
				if grep $rln $modfile > /dev/null 2>&1; then dis='Disabled'; fi
		printf "%-7s" $cnt; echo $rln $dis "$msg"
		done
		echo
		echo '----------------------------------------------------------'
		echo "Type in ONE rule number that you'd like to disable. Pick the most commonly triggered that isn't already disabled."
		echo "If you don't want to disable it, just use Ctrl+C to terminate the script now."

		read rulenumber
				# see if input number is one of the top ten
		if  $topten = *$rulenumber*  
		then
								#If it exists, process it and add to it
								if ls $modfile > /dev/null 2>&1
								then
										if  $existingrules = *$rulenumber* 
												then
												echo "This rule is already Disabled, pleease try again."
												exit 1
										fi

										#make a temp file and then move modfile to a backup in case we miGht bork it
										cp $modfile $tmpfile
										mv $modfile $modfile.bak

										#Delete all the stUff we handle in the file - just modsec stuff
										sed -i '/IfModule Mod_sec/d' $tmpfile
										sed -i '/LocationMatch/d' $tmpfile
										sed -i '/SecRuleRemoveById/d' $tmpfile
										sed -i '/^$/d' $tmpfile

										#remove any extra ifmodule and its matching line as a pair
										sed -i '/<IfModule mod_security2.c>/{; N; /<\/IfModule>/d}' $tmpfile

										existingrules="$existingrules $rulenumber"
										#spit them back into the new modfile
										echo "<IfModule mod_security2.c>" >> $modfile
										for rule in $existingrules
										do echo SecRuleRemoveById $rule >> $modfile
										done
										echo "</IfModule>" >> $modfile
										cat $tmpfile >> $modfile
										rm -f $tmpfile
										# modify $httpdconf to uncomment the line for this modsec file to be included
										sed  -i "\@std/2_2/$user/$domain/@ s@# @@" $httpdconf
										echo '----------------------------------------------------------'
										echo "Mod_Security rule $rulenumber disabled for $domain with username $user, in addition to \
										rules that were already disabled."
										echo "Now distilling and restarting  apache. If it won't start, look in $modfile for errors."
										echo "Restore the original which is in $modfile.bak if necessary."
										/usr/local/cpanel/bin/apache_conf_distiller --update && service httpd restart
										#otherwise just make a new one
										else
											mkdir -p /usr/local/apache/conf/userdata/std/2_2/$user/$domain
											#Added a bit of logic to handle SSL vhosts. Looks for existence of the SSL 
											if grep -l "ssl/2_2/$user/$domain" $httpdconf >/dev/null
												then 
													sed  -i "\@ssl/2_2/$user/$domain/@ s@# @@" $httpdconf
														mkdir -p /usr/local/apache/conf/userdata/ssl/2_2/$user/$domain
														ln -s $modfile $sslmodfile
											fi
										echo "<IfModule mod_security2.c>"  >> $modfile
										echo "SecRuleRemoveById" $rulenumber  >> $modfile
										echo "</IfModule>" >> $modfile
										sed  -i "\@std/2_2/$user/$domain/@ s@# @@" $httpdconf
										echo '----------------------------------------------------------'
										echo "$modfile modified"
										echo "Mod_Security Rule $rulenumber disabled for $domain with username $user"
										echo "Thank you for using Whack-A-Mod 2.0 please send feedback to RyanF"
										echo "Distilling and restarting apache now"
							  /usr/local/cpanel/bin/apache_conf_distiller --update && service httpd restart
								fi
		else
				echo "Fatal error: $rulenumber is not a valid selection. Game Over."
		fi
else echo "No modsec violaions for $domain found. Utter failure."
fi


else
		echo "Critical error: Either $modfile does not exist in httpd.conf or the path $modfile does not exist in the file system."
fi
		}

whackip(){
echo Searching error_log for ModSec violations, one moment please...
topten=`grep $domain /usr/local/apache/logs/error_log | grep ModSec | grep -o '[0-9]\{6\}' | sort | uniq -c | sort -n |sed 's/^[ ]*//' | sed 's/[ ]/:/' | tail -n10`
if [ ! -z "$topten" ];
then

 echo '----------------------------------------------------------'
		echo "Count  Rule    Rule Description (if available)"


		for rule in $topten

		do
				cnt=`echo $rule | cut -d":" -f1`
				rln=`echo $rule | cut -d":" -f2`
				msg=`grep $rln /usr/local/apache/conf/mod_sec/*.conf | grep msg |sed 's/.*msg:' | sed 's/,id.*' | sed "s/'g"| sed 's/"g'`
				printf "%-7s" $cnt; echo $rln "$msg"
		done
		echo
		echo "Please note above modsec violations. This tool cannot disable them in IP mode. Please re-run tool with a domain name as an argument."
fi
}

whacksummary(){
echo Searching error_log for ModSec violations, one moment please...
toptwenty=`grep ModSec /usr/local/apache/logs/error_log | grep -o '[0-9]\{6\}' | sort | uniq -c | sort -n |sed 's/^[ ]*//' | sed 's/[ ]/:/'| tail -020`
if [ ! -z "$toptwenty" ];
then

		echo '----------------------------------------------------------'
		echo "Count  Rule    Rule Description (if available)"


		for rule in $toptwenty

		do
				cnt=`echo $rule | cut -d":" -f1`
				rln=`echo $rule | cut -d":" -f2`
				msg=`grep $rln /usr/local/apache/conf/mod_sec/*.conf | grep msg |sed 's/.*msg:' | sed 's/,id.*' | sed "s/'g"| sed 's/"g'`
				printf "%-7s" $cnt; echo $rln "$msg"
		done
		echo
		echo "This is a ModSec rule count for the whole server and does not represent anything that can be disabled in Summary mode."
fi


}

if [ "$1" == "" ]; then
cat <<_EOF_
##############################################################################
# ModSec Whack-A-Mole script v2.3.1
#
# 2014-2017 Ryan Flowers
#
# Shows you the most commonly violated ModSecuritY rules by Domain name
# and then gives you the opportunity to disable the rule. Now supports disabling 
# multiple rules at once.
#


whackamodsecrule domainname.com
or
whackamodsecrule 12.34.56.78

##############################################################################

You can get a list of the top 20 for the whole server

whackamodsecrule summary

##############################################################################

_EOF_

  exit 1
		else

domain=$1
		if [ $domain == "summary" ]
		then
				whacksummary
		else
				if grep -l $domain /etc/userdomains >/dev/null
						then whackdom $domain
				else
						if  $domain =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ 
						then echo 'IP address detected. Please note that results will be based on IP not domain.'
						whackip {$domain}
						else echo "The domain $domain does not exist. Try again.";
						fi
				fi
		fi
fi