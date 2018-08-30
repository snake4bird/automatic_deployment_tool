#!/bin/bash
################################################################
#Name:		maad
#Filename:  aad/m
#Desc:		console menu for agent automatic deployment
#Author:	Bird
#Date:		2018-07-11
#Version:   1.0
#History:
#           基础功能
# 20180713: +编码解码解析控制机制
# 20180716: +日志记录
# 20180718: +配置文件解析
# 20180719: +任务文件解析
# 20180720: +命令行参数解析
# 20180730: +任务列表
# 20180801: +任务列表菜单选择
# 20180803: +任务详单，任务项列表
# 20180807: +任务详细菜单选择
# 20180809: +任务项处理
# 20180813: +本地任务命令处理
# 20180815: +本地命令并行处理
#           远程控制功能
# 20180816: +远程连接
# 20180817: +远程命令下发
# 20180820: +远程命令执行
# 20180821: +远程命令并行处理
# 20180822: +远程命令交互处理
# 20180823: +远程命令监控
# 20180824: +分级日志记录
#           任务状态管理功能
# 20180827: +任务状态记录
# 20180828: +任务状态显示
# 20180829: +任务状态统计
# 20180830: +任务状态控制
# 20180831: +任务状态菜单选择
# 20180903: +任务项状态查看
#           agent部署命令配置测试实施
# 20180907: +OSagent
# 20180911: +DB2agent
# 20180913: +MQagent
# 20180917: +ORACLEagent
# 20180919: +MYSQLagent
# 20180921: +WASagent
# 20180925: +CICSagent
# 20180927: +HMCagent
#           未实现功能 TODO LIST
#           定期日志清理
#           任务状态总揽
#           任务状态分类显示
#           任务状态动态刷新
#           部署覆盖策略
#           ...
################################################################

#参数
#  maad task=任务文件路径
#  maad task=任务文件路径 ip=指定节点IP或host=HOSTNAME
#  maad task=任务文件路径 ip=指定节点IP或host=HOSTNAME agent=指定Agent [其它需要的key=value]
#	 这是最终实际运行的参数指定方式
#  maad
#    默认处理任务配置目录下的所有任务文件，根据任务文件中的subject设置显示菜单
#    任务配置目录，缺省为 task
#    --task=任务文件路径
#    --ip=node ip, 指定节点IP
#    --host=hostname 指定节点HOSTNAME
#    --agent=agentname   指定Agent，OS|DB2|MQ|CICS|ORACLE|WAS|HMC
#						 OSagent|os|ux|lz|DB2agent|db2|ud|MQagent|mq|CICSagent|cics|t8|Oracle|rz|WAS|yn|HMC|ph|?|
#    部署参数
#    --username=username   部署过程使用的用户，一般为root
#    --password=password   部署过程使用的用户密码
#    部署选项
#    --force=redeploy
#    --install=force|alert|ignore 安装目录已存在时，force强制覆盖安装，alert报告安装已存在，ignore略过安装步骤
#    --config=force|ignore 安装目录已存在时，force强制重新配置，ignore略过配置步骤
#    --check=force|ignore  安装目录已存在时，force强制重新配置，ignore略过检查步骤
#    --start=true|false    安装配置完成后，是否启动agent
#    ...                   各个agent部署时需要的参数
#

#任务文件格式
#   #开头作为注释行，可以出现在文件中任何位置
#   空行，可以出现在文件中任何位置
#	一行中两端的空白将被清除
#	
#   文件头
#   subject=文件内容说明，将作为菜单项显示，如：部署所有网银DB2监控代理
#		如果没有指定，不会在菜单项中显示
#	batch=YYYYmmdd，任务起始日期，指定日期之前已部署agent将被强制覆盖安装，指定日期之后已部署agent将略过部署步骤
#		如果没有指定，以文件日期作为任务起始日期
#		目的：可以在任务文件中追加部署节点
#   remote=remote server
#	username=root
#	password=123456
#   [key=value] 其它通用参数设置，key只能包含小写字母、数字和下划线
#   
#   任务配置主体，以三个以上连续井号开头的一行开始，至文件结束
#   ###############################################################
#	节点IP 节点HOSTNAME 指定Agent [[key=value][ key=value]*]
#   	作为校验手段，如果IP和HOSTNAME与实际对不上，相关节点的部署过程将报错退出
#
#

#配置信息覆盖关系
#  0. <arguments>
#  1. .etc/setting.txt
#  2. <task file>
#  3. <agent setting>
#  4. <arguments>
#


#备忘：
#
#杀进程命令： ps -ef | grep -E "/m( .*)?$" | grep -v " grep " | awk '{print $2}' | xargs kill -9
#


#通用设置
export LANG=zh_CN.utf8
export LC_ALL=zh_CN.utf8

#改变工作目录到当前脚本所在路径
export CUR_FILE="$0"
export CUR_DIR="`echo $0 | sed 's/[^\/]*$//'`"
if [[ "${CUR_DIR}" ]]; then
    cd "${CUR_DIR}"
	workdir="`pwd`"
	if [[ "${workdir}" != "/" ]]; then
		workdir="${workdir}/"
	fi
	CUR_FILE="${CUR_FILE/${CUR_DIR}/${workdir}}"
	CUR_DIR="${workdir%/}"
fi
#echo "pwd=`pwd`    CUR_DIR=${CUR_DIR}    workdir=${workdir}    CUR_FILE=${CUR_FILE}"

#仅支持通过SSH连接
export HOSTIP=`awk -F ' ' {'print $3'} <<< $SSH_CONNECTION`

#禁止中断
#trap '' INT

#自定义字段分割符，系统缺省为任意空白字符
#export IFS=

#正则表达式
pt_empty="^[ \t\r\b\n]*$"
pt_comments="^[ \t]*#.*$"
pt_number="^[0-9]+$"
pt_numbers="^[0-9]+([ ]+[0-9]+)+$"
pt_ip="^[0-9]+(\.[0-9]+){3}$"
pt_trace="^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{3} \[[0-9._-]+\] \[[^\]]*\] .*$"
pt_kvpair="^.*\=.*$" 
#严格变量名的键值对
pt_strict_kvpair="^[a-zA-Z_][a-zA-Z_0-9]*\=.*$"
#多行值表达的键值对
pt_multiline_kvpair_start="^[a-zA-Z_][a-zA-Z_0-9]+:=?.*$"
pt_multiline_special_setting_flag="^.*:[ \t\r\b\n]*$"
pt_multiline_end="^!!.*"
#特殊字符常量
alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
newline="
"
tab="	"
space=" "
quote='"'
single_quote="'"
point_quote='`'
slash='/'
backslash='\'
symbol_at='@'
dollar='$'
brace='{'
dash='-'

#命令行参数转化为配置信息
__args_in__=$@
__args_out__=""
arguments() {
	if [[ "${__args_out__}" == "" ]]; then
		for arg in ${__args_in__}
		do
			__args_out__="${__args_out__}${arg}${newline}"
		done
	fi
	echo "${__args_out__}"
}

#存在警告或错误信息时，清屏保留告警信息
warning_message=""
cls() {
	clear
	if [[ "${warning_message}" != "" ]]; then
		echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
		echo "${warning_message}${newline}"
		echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	fi
}

export __mid__=0
export id=0
gen_id() {
	__mid__=`expr ${__mid__} + 1`
	id=`expr ${__mid__} "*" 100000 + $$`
}

#输出调试信息
tl_none=''      #level 0 不输出任何信息
tl_fatal='F'    #level 1 输出严重错误信息
tl_error='E'    #level 2 输出一般错误信息
tl_warn='W'     #level 3 输出警告信息
tl_status='S'   #level 4 状态信息
tl_info='I'     #level 5 输出提示信息
tl_proc='P'     #level 6 输出处理流程信息
tl_detail='D'   #level 7 输出数据处理信息
tl_variable='V' #level 8 输出变量信息，仅用于开发期间
tl_debug='X'    #level 9 输出详细调试信息，仅用于开发期间
tl_all='A'      #level a 输出任何信息，仅用于开发期间
AAD_LOG="FEWSIPD"  #默认输出调试信息级别
AAD_CMD="FEWSIPD"
if [[ "${AAD_TRACE}" == "" ]]; then
	export AAD_TRACE="FEWSI" #默认调试信息跟踪级别
fi
KEEP_AAD_TRACE=""
trace() {
	level="$1"
	msg="$2"
	if [[ "${msg}" =~ $pt_trace ]]; then
		local olvl="${msg#*] [}"
		level="${olvl%%] *}"
	fi
	if [[ ! "${msg}" =~ $pt_trace ]]; then
		dtns=`date +"%Y-%m-%d %H:%M:%S.%N"`
		dtms=${dtns:0:23}
		msg="${dtms} [$$] [${level/_/}] ${msg}"
	fi
	if [[ $level == *F* || $level == *E* || $level == *W* ]]; then
		warning_message="${warning_message}${newline}${msg}"
	fi
	if [[ "$level" == _* || "${AAD_TRACE}" == *${level/_/}* ]]; then
		if [[ "$level" == _* || "${AAD_LOG}" == *${level/_/}* ]]; then
			#输出到日志文件和console
			echo "${msg}" | tee -a -i "${HOME}/aadlogs/log.`date +"%Y%m%d"`.txt"
		else
			#仅输出到console
			echo "${msg}"
		fi
	else
		#仅输出到日志文件
		if [[ "${AAD_LOG}" == *${level/_/}* ]]; then
			echo "${msg}" >> "${HOME}/aadlogs/log.`date +"%Y%m%d"`.txt"
		fi
	fi
}

#对文件内容中的空白字符进行编码，以方便后续解析处理控制
encode_file() {
	cat $1 | sed -e "s/+/+S-/g" -e "s/\\\\/+P-/g" -e "s/\t/+T-/g" -e "s/ /+B-/g" -e "s/"'"'"/+Q-/g" -e "s/'/+q-/g" -e "s/\`/+x-/g" -e "s/\r//g" -e "s/\\$/+D-/g" -e "s/@@/+A-/g" -e "s/$/+0-&/g"
}

#编码文本
encode_text() {
	sed -e "s/+/+S-/g" -e "s/\\\\/+P-/g" -e "s/\t/+T-/g" -e "s/ /+B-/g" -e "s/"'"'"/+Q-/g" -e "s/'/+q-/g" -e "s/\`/+x-/g" -e "s/\r//g" -e "s/\\$/+D-/g" -e "s/@@/+A-/g" -e "s/$/+0-&/g" <<< "$1"
}

#编码包括换行符在内的多行文本
encode_lines() {
	sed -e "s/+/+S-/g" -e "s/\\\\/+P-/g" -e "s/\t/+T-/g" -e "s/ /+B-/g" -e "s/"'"'"/+Q-/g" -e "s/'/+q-/g" -e "s/\`/+x-/g" -e "s/\r//g" -e "s/\\$/+D-/g" -e "s/@@/+A-/g" -e "s/$/+N-&/g" <<< "$1"
}

#解码空白字符
decode_whitespace() {
	LINE=$1
	LINE=${LINE//+0-/}            #行尾标记$
	LINE=${LINE//+B-/${space}}    #空格blank
	LINE=${LINE//+T-/${tab}}      #制表符tab
	LINE=${LINE//+N-/${newline}}  #换行符
	echo "${LINE}"
}

#解码所有转义字符
decode() {
	LINE=$1
	LINE=${LINE//+0-/}                 #行尾标记$
	LINE=${LINE//+D-/$}                #${var}，变量标记
	LINE=${LINE//+A-/@@}               #@{var}，常量标记，用两个@@代表原始的@符号
	LINE=${LINE//+B-/${space}}         #空格blank
	LINE=${LINE//+T-/${tab}}           #制表符tab
	LINE=${LINE//+N-/${newline}}       #换行符
	LINE=${LINE//+P-/${backslash}}     #反斜线
	LINE=${LINE//+Q-/${quote}}         #双引号
	LINE=${LINE//+q-/${single_quote}}  #单引号
	LINE=${LINE//+x-/${point_quote}}   #点号
	LINE=${LINE//+S-/+}                #转义标记+
	echo "${LINE}"
}

#去掉字符串两边的空白字符
trim() {
	local str="$1"
	local sss=""
	while [[ "${str}" != "${sss}" ]]; do
		sss="${str}"
		str="${str#${space}}"
		str="${str%${space}}"
		str="${str#${tab}}"
		str="${str%${tab}}"
	done
	echo "${str}"
}

#替换配置变量
value() {
	local cmdscript="$1"
	local cmdkey="$2"
	local cmdlines=""
	local ecount="."
	local linecount=""
	#"env | grep -v -E "'"'"^[A-Z0-9_]+=.*"'"'":${newline}`env | grep -v -E "^[A-Z0-9_]+=.*"`"
	#trace A "env${newline}`env | sort | grep -E "[a-z0-9_]+="`" >> "${HOME}/aadlogs/value.log"
	#trace A "import value: ${cmdkey}=${cmdscript}" >> "${HOME}/aadlogs/value.log"
	while [[ "${cmdscript}" != "${cmdlines}" && ${#ecount} -lt 10 ]]; do
		cmdlines=${cmdscript}
		cmdlinesarray=(`encode_text "${cmdlines}"`)
		cmdscript=""
		linecount="."
		for cmdline in ${cmdlinesarray[@]}; do
			#替换配置变量，编码后的cmdline中不会有$或@@
			#trace A "import vars A ${#ecount}: ${cmdkey}[${#linecount}]=${cmdline}" >> "${HOME}/aadlogs/value.log"
			cmdline="${cmdline//'@{'/${dollar}${brace}}"
			#trace A "import vars B ${#ecount}: ${cmdkey}[${#linecount}]=${cmdline}" >> "${HOME}/aadlogs/value.log"
			cmdline="`eval echo '"'${cmdline}'"'`"
			#trace A "import vars C ${#ecount}: ${cmdkey}[${#linecount}]=${cmdline}" >> "${HOME}/aadlogs/value.log"
			cmdline=`decode "${cmdline}"`
			#trace A "import vars D ${#ecount}: ${cmdkey}[${#linecount}]=${cmdline}" >> "${HOME}/aadlogs/value.log"
			if [[ ${#linecount} -gt 1 ]]; then
				cmdscript="${cmdscript}${newline}"
			fi
			cmdscript="${cmdscript}${cmdline}"
			linecount="${linecount}."
		done
		ecount="${ecount}."
	done
	#trace $tl_proc "value: ${cmdkey}=${cmdscript}" >> "${HOME}/aadlogs/value.log"
	echo "${cmdscript//@@/@}"
}

#导出变量设置
shift_key_n=0
export_setting() {
	local key=$1
	local value=$2
	trace V "export setting ${key}=${value}"
	local pt_recurse_var="@""{${key}}"
	local pt_recurse_val="$""{${key}}"
	if [[ "${value}" == *$pt_recurse_var* ]]; then #引用自身变量代入
		#保留上一个值
		shift_key_n=`expr ${shift_key_n} + 1`
		last_value="`eval echo '"'${pt_recurse_val}'"'`"
		trace V "push last value aadv_${shift_key_n}=${last_value}" 
		eval 'export "aadv_${shift_key_n}=${last_value}"'
		#改变自引用指向上一个值
		aadv_key="@""{aadv_${shift_key_n}""}"
		value=${value//${pt_recurse_var}/${aadv_key}}
		trace V "export setting ${key}=${value}"
	fi
	eval 'export "${key}=${value}"'
}

#专项设置，针对特定节点的设置
#第一个参数如果不是键值对，则设为特定节点IP
#第二个参数如果不是键值对，则设为特定节点HOSTNAME
#第三个参数如果不是键值对，则设为特定节点要安装的agent
export aad_iha_count=0
special_setting() {
	local fields=($1)
	local finfo=""
	local fcount=""
	local fvals=""
	local n_ip=""
	local n_host=""
	local f_ip=""
	local f_host=""
	local f_agent=""
	for f in ${fields[@]}
	do
		f=`decode "${f}"` #解码
		f=`trim "${f}"`
		if [[ ! "${f}" =~ $pt_strict_kvpair && "${fvals}" == "" && "${#fcount}" < "4" ]]; then
			trace V "->${#fcount}:${f}"
			kf=${f}
			kf=${kf//./_}
			kf=${kf//-/_}
			if [[ "${#fcount}" == "0" ]]; then
				n_ip="${f}"
				f_ip="${kf}"
			elif [[ "${#fcount}" == "1" ]]; then
				n_host="${f}"
				f_host="${kf}"
				export ip_host_${f_ip}=${n_host}
			elif [[ "${#fcount}" == "2" ]]; then
				f_agent="${f}"
				export aad_iha_count=`expr ${aad_iha_count} + 1`
				local hak="`printf "aad_iha_%05d" ${aad_iha_count}`"
				local has="$""{${hak}}"
				local ahk="aad_ahi_${f_ip}_${f_host}_${f_agent}"
				local ahs="$""{${ahk}}"
				if [[ "`eval echo '"'${ahs}'"'`" == "" ]]; then
					export "${hak}=${n_ip} ${n_host} ${f_agent}"
					export "aad_ahi_${f_ip}_${f_host}_${f_agent}=${aad_iha_count}"
				else
					if [[ ! -d "${task}" &&  -e "${task}" && "${task_file_analyzed}" != "${task}" ]]; then #task指定的是任务文件
						trace $tl_warn "部署任务重复定义，${settings_file} ${#count}: ${n_ip} ${n_host} ${f_agent}"
					fi
				fi
			fi
		else
			fvals="+"
			trace V "+-${#fcount}:${f}"
			if [[ "${finfo}" == "" ]]; then
				finfo="${f}"
			else
				finfo="${finfo} ${f}"
			fi
			export "aad_${f_host}_${f_agent}_${f}"
		fi
		fcount="$fcount+"
	done
	trace $tl_detail "f_ip=${f_ip} f_host=${f_host} f_agent=${f_agent} ${finfo}"
}

#解析经过编码的配置信息
analyze_settings() {
	local lines=$1
	local flag=$2
	local count=""
	local export_count=""
	local multiline_kvp_key=""
	local multiline_kvp_value=""
	local multiline_special_keys=""
	local multiline_special_setting=""
	trace X "${settings_file} (${#lines} encoded chars)${newline}${lines}" #编码过的全部内容
	for line in $lines #逐行处理
	do
		count="${count}."
		trace A "${settings_file} ${#count}: encoded[${line}]" #编码过的一行内容
		line=`decode "${line}"` #解码
		trace X "${settings_file} ${#count}: ${line}" #解码后的一行内容
		if [[ "${multiline_kvp_key}" != "" ]]; then #多行参数值处理
			if [[ "${line}" =~ $pt_multiline_end ]]; then #多行参数值结束，目前不支持多行参数的嵌套
				export_setting "${multiline_kvp_key}" "${multiline_kvp_value}" #执行变量导出命令
				export_count="${export_count}."
				multiline_kvp_key=""
				multiline_kvp_value=""
			else
				multiline_kvp_value="${multiline_kvp_value}${newline}${line}"
			fi
		elif [[ "${multiline_special_keys}" != "" ]]; then #多行特殊设置参数值处理
			if [[ "${line}" =~ $pt_multiline_end ]]; then #多行参数值结束，目前不支持多行参数的嵌套
				if [[ "${flag}" == "" ]]; then
					special_setting "${multiline_special_keys}${newline}`encode_text "${multiline_special_setting}"`"
				fi
				multiline_special_keys=""
				multiline_special_setting=""
			else
				multiline_special_setting="${multiline_special_setting}${newline}${line}"
			fi
		elif [[ "${line}" =~ $pt_multiline_kvpair_start ]]; then #多行值开始
			multiline_kvp_key=${line%%=*}
			multiline_kvp_key=${multiline_kvp_key/%:/} # key:multiline value 或 key:=multiline value
			multiline_kvp_value=${line#*:}
			multiline_kvp_value=${multiline_kvp_value#=}
		elif [[ "${line}" =~ $pt_strict_kvpair ]]; then #规范键值对
			export_setting "${line%%=*}" "${line#*=}" #执行变量导出命令
			export_count="${export_count}."
		elif [[ ! "${line}" =~ $pt_comments && ! "${line}" =~ $pt_empty ]]; then #不是空行或注释行
			#line=`decode_whitespace "${line}"` #只解码空白字符
			if [[ "${line}" =~ $pt_multiline_special_setting_flag ]]; then #内容中存在空白字符，用换行分割多个配置字段，内容中不能再有换行符
				multiline_special_keys=${line%%:*}
				multiline_special_setting=${line#*:}
			else
				if [[ "${flag}" == "" ]]; then
					special_setting "${line}" #空白分割的多个配置字段
				fi
			fi
		#else skip 跳过空行和注释行
		fi
		
		if [[ "$export_limit" =~ pt_number && ${#export_count} > $export_limit ]]; then
			break
		fi
	done
	trace V "${settings_file} <EOF>"
	return ${#export_count}
}

#解析配置文件
analyze_setting_file() {
	local settings_file=$1
	local lines=`encode_file "${settings_file}"`
	analyze_settings "$lines" "$2"
}

#解析多行文本配置信息
analyze_setting_text() {
	local settings_file="text"
	local lines=`encode_text "$1"`
	analyze_settings "$lines" "$2"
}

#解析单行配置信息
analyze_setting_line() {
	local settings_file="line"
	local lines=`encode_text "$1"`
	analyze_settings "$lines" "$2"
}

#获取指定目录下的文件
list_files() {
	local fdir=$1
	if [[ "${fdir}" == "" ]]; then
		fdir="."
	elif [[ "${fdir}" != "/" ]]; then
		fdir="${fdir/%\//}" #去掉可能的后缀斜线
	fi
	local files=(`ls -l "${fdir}" | grep -v "^d" | awk -F ' ' {'print $9'} | grep -v '^$'`)
	#补全文件路径
	count=""
	for tf in ${files[@]}
	do
		files[${#count}]="${fdir}/${tf}"
		count="${count}."
	done
	echo "${files[*]}"
}

#解析任务配置文件
analyze_taskfile() {
	export subject=""
	export batch=""
	analyze_setting_file "$1" "$2"
	if [[ "${subject}" == "" ]]; then
		subject="$1"
	fi
	if [[ "${batch}" == "" ]]; then
		batch="`date +%Y-%m-%d -r "$1"`"
	fi
}

#用户界面输出
uiout() {
	echo "$1"
}

export INPUT=""
read_input() {
	receive_max_number=$1
	local AK_INPUT="\000"
	if [[ "$2" ]]; then
		read -t$2 -n1 AK_INPUT #读取输入
	else
		read -n1 AK_INPUT #读取输入
	fi
	if [[ "${AK_INPUT}" =~ $pt_number && $receive_max_number -ge 9 ]]; then
		while [[ "${AK_INPUT}" =~ $pt_number ]]; do
			read -n1 NK_INPUT #读取输入
			if [[ "${NK_INPUT}" == "" ]]; then
				break
			elif [[ "${NK_INPUT}" == " " ]]; then
				echo
				break
			else
				AK_INPUT="${AK_INPUT}${NK_INPUT}"
			fi
		done
		if [[ "${AK_INPUT}" =~ $pt_number ]]; then
			INPUT="${AK_INPUT}"
			return
		else
			AK_INPUT=""
		fi
	fi
	local INPUT_CODE=(`printf "${AK_INPUT}" | od -An -t dC`)
	if [[ "${INPUT_CODE}" == "27" ]]; then
		#功能键处理，需要清空键盘缓冲区
		AK_INPUT="^["
		local FK_INPUT="?"
		while [[ "${FK_INPUT}" ]]
		do
			FK_INPUT=""
			read -s -t1 -n1 FK_INPUT
			local FK_INPUT_CODE=(`printf "${FK_INPUT}" | od -An -t dC`)
			if [[ "${FK_INPUT}" ]]; then
				AK_INPUT="${AK_INPUT}${FK_INPUT}"
				INPUT_CODE="${INPUT_CODE} ${FK_INPUT_CODE}"
			fi
		done
	fi
	trace $tl_detail "input=${AK_INPUT}[${INPUT_CODE}]"
	if [[ "${CASE_SENSITIVE}" != "1" ]]
	then
		AK_INPUT=`tr "[a-z]" "[A-Z]" <<< "${AK_INPUT}"` 
	fi
	if [[ "${AK_INPUT}" != "\000" ]]; then
		printf "\r%s%80s\n" "${AK_INPUT}" ""
		INPUT="${AK_INPUT}"
	fi
}

#选择部署任务配置文件
select_task() {
	#获取任务文件列表
	task_files=(`eval list_files '"'${task}'"'`)
	trace V "found ${#task_files[@]} taskfiles:${newline}${task_files[*]}"
	if [[ ${#task_files[@]} == 0 ]]; then
		uiout "没有找到部署任务配置文件，请将部署任务配置文件放到指定目录(${CUR_DIR}/task)下" 
		return 101
	fi
	while true
	do
		INPUT=""
		while [[ ! ("${INPUT}" =~ $pt_number && -e "${task_files[${INPUT}]}") ]]
		do
			cls
			uiout ""
			uiout "选择部署任务：" 
			tfs=""
			export export_limit=2
			for tf in ${task_files[@]}
			do
				analyze_taskfile "${tf}" "g"
				title=$(encode_text "${tf}${tab}${subject}  (${batch})")
				tfs="${tfs}${batch}!${title}${newline}"
			done
			export export_limit=
			#以部署时间倒序的前10个文件
			tfs=$(echo "$tfs" | sort -r | head -10)
			count=""
			for tf in ${tfs[@]}
			do
				tf=$(decode "${tf#*!}")
				task_files[${#count}]="${tf%${tab}*}"
				tf="${tf#*${tab}}"
				uiout "${#count}: ${tf}"
				count="${count}."
			done
			uiout ""
			uiout "请输入对应任务的编号，输入x退出：" 
			read_input
			trace $tl_proc "select_task INPUT="'"'"${INPUT}"'"'""
			if [[ "${INPUT}" == "x" || "${INPUT}" == "X" ]]; then
				return 0
			fi
		done
		trace $tl_proc "task=${task_files[${INPUT}]}"
		"${CUR_FILE}" "task=${task_files[${INPUT}]}"
	done
}

task_status() {
	local staskstatus=""
	if [[ -e "${taskstatusfile}" ]]; then
		staskstatus=`cat "${taskstatusfile}"`
	fi
	local line
	while read line
	do
		local fs=($line)
		local status=`grep "${fs[2]} ${fs[3]} ${fs[4]}" <<< "${staskstatus}" | awk '{printf "%s",$4}'`
		if [[ "${status}" == "" ]]; then
			status="未部署"
		fi
		printf "%5d : %15s %16s %16s       %s\n" "${fs[0]}" "${fs[2]}" "${fs[3]}" "${fs[4]}" "${status}"
	done
}

#列出当前部署任务的详细列表
task_list() {
	env | grep -E "aad_iha_[0-9]+=" | sed -e "s/aad_iha_//g" -e "s/=/ /g" | sort | sed -e "s/^0*//g" | awk '{printf "%5d : %15s %16s %16s\n",$1,$2,$3,$4}' | task_status
}

task_status_info() {
	cat "${HOME}/aadlogs/$2_$3_$4.txt" | grep -E "[0-9:]+ \\[[0-9\\._-]+\\] \\[[$1]\\] .*"
}

run_task() {
	local force=$1
	local ip=$2
	local host=$3
	local agent=$4
	
	local status=`grep "${ip} ${host} ${agent}" "${taskstatusfile}" | awk '{printf "%s",$4}'`
	if [[ "${force}" != "redeploy" ]]; then
		if [[ "${status}" == "部署完成" ]]; then
			trace $tl_detail "${ip} ${host} ${agent} 已完成部署"
			return 0
		fi
	fi
	
	if [[ "${status}" != "" && "${status}" != "部署完成" && "${status/%[*}" != "部署失败" ]]; then
		trace $tl_detail "${ip} ${host} ${agent} 貌似正在执行，检查一下是否真的正在执行"
		local really=`ps -ef | grep -E "${CUR_FILE} id=.*" | grep -v " grep " | grep "ip=${ip} host=${host} agent=${agent}"`
		if [[ "${really}" ]]; then
			trace $tl_detail "${ip} ${host} ${agent} 正在部署，不能重复执行"
			return 0
		fi
	fi

	gen_id
	local output="${HOME}/aadlogs/${ip}_${host}_${agent}.txt"
	${CUR_FILE} "id=${id}" "AAD_TRACE=${AAD_CMD}" "force=${force}" "task=${task}" "ip=${ip}" "host=${host}" "agent=${agent}" 2>&1 1>"${output}" &
	local pid=$!
	#wait $pid
	return 0
}

#确认部署任务
default_refresh_timeout=5
confirm_task() {
	local refresh_timeout=$default_refresh_timeout
	while true
	do
		cls
		uiout ""
		uiout "请确认部署任务 - ${subject}："
		uiout ""
		uiout "                节点IP          节点名称        部署Agent        状态"
		uiout " ---------------------------------------------------------------------------"
		
		task_list
		
		uiout ""
		if [[ -e "${taskstatusfile}" ]]; then
			uiout "输入d重新部署未完成任务，输入q返回，请输入对应子任务编号查看详细状态信息："
		else
			uiout "输入d确认部署，输入q取消任务，请输入对应子任务编号执行特定任务："
		fi
		local refresh_count=$refresh_timeout
		refresh_timeout=$default_refresh_timeout
		INPUT="\000"
		while [[ "${INPUT}" == "\000" && $refresh_count -gt 0 ]]
		do
			printf "%s\r" "${refresh_count}秒后自动刷新状态或按回车键刷新"
			refresh_count=`expr ${refresh_count} - 1`
			read_input $aad_iha_count 1
		done
		
		trace $tl_proc "confirm_task INPUT="'"'"${INPUT}"'"'""
		if [[ "${INPUT}" == "q" || "${INPUT}" == "Q" ]]; then
			trace $tl_proc "任务取消"
			return 0
		elif [[ "${INPUT}" =~ $pt_number ]]; then
			trace $tl_proc "部署指定任务"
			local hak="`printf "aad_iha_%05d" ${INPUT}`"
			local has="$""{${hak}}"
			local hav="`eval echo '"'${has}'"'`"
			if [[ "${hav}" == "" ]]; then
				uiout ""
				uiout "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
				uiout "!!!                                  !!!"
				uiout "!!!     没有找到对应编号的子任务     !!!"
				uiout "!!!                                  !!!"
				uiout "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
				uiout "按任意键继续"
				read_input
			else
				local iha=(${hav})
				INPUT="i"
				local lvl="FEW"
				while [[ "${lvl}" != "${AAD_CMD}" && ("${INPUT}" == "i" || "${INPUT}" == "I") ]]
				do
					local n=`expr ${#lvl} + 1`
					lvl="${AAD_CMD:0:$n}"
					task_status_info "${lvl}" "${iha[0]}" "${iha[1]}" "${iha[2]}"
					uiout ""
					if [[ "${lvl}" == "${AAD_CMD}" ]]; then
						uiout "输入r重新部署，按其它键返回"
					else
						uiout "输入r重新部署，输入i查看更详细信息，按其它键返回"
					fi
					read_input
				done
				if [[ "${INPUT}" == "r" || "${INPUT}" == "R" ]]; then
					if [[ "${AAD_RECONFIRM}" == "1" ]]; then
						uiout "按Y键，开始部署${hav}"
						read_input
					else
						INPUT="Y"
					fi
					if [[ "${INPUT}" == "y" || "${INPUT}" == "Y" ]]; then
						uiout ""
						run_task "redeploy" "${iha[0]}" "${iha[1]}" "${iha[2]}"
						uiout ""
						local pcount=`ps -ef | grep -v " grep " | grep -E "${CUR_FILE} id=[0-9]+$$" | grep "force=" | awk '{printf " %s ",$2}'| wc -w`
						uiout "${pcount}部署任务正在执行，1秒自动返回查看状态"
						read_input "" 1
						refresh_timeout=2
					else
						uiout "取消部署，按任意键继续"
						read_input
					fi
				fi
			fi
		elif [[ "${INPUT}" == "d" || "${INPUT}" == "D" ]]; then
			trace $tl_proc "部署任务-${subject}"
			if [[ "${AAD_RECONFIRM}" == "1" ]]; then
				uiout "按Y键，开始部署${subject}"
				read_input
			else
				INPUT="Y"
			fi
			if [[ "${INPUT}" == "y" || "${INPUT}" == "Y" ]]; then
				uiout ""
				local n=0
				while [[ $n -le $aad_iha_count ]]; do
					n=`expr ${n} + 1`
					local hak="`printf "aad_iha_%05d" ${n}`"
					local has="$""{${hak}}"
					local hav="`eval echo '"'${has}'"'`"
					local iha=(${hav})
					if [[ "${iha[0]}" =~ $pt_ip && "${iha[1]}" != "" && "${iha[2]}" != "" ]]; then
						run_task "" "${iha[0]}" "${iha[1]}" "${iha[2]}"
					fi
				done
				uiout ""
				local pcount=`ps -ef | grep -v " grep " | grep -E "${CUR_FILE} id=[0-9]+$$" | grep "force=" | awk '{printf " %s ",$2}'| wc -w`
				uiout "${pcount}部署任务正在执行，1秒自动返回查看状态"
				read_input "" 1
				refresh_timeout=2
			else
				uiout "取消部署，按任意键返回"
				read_input
				return 0
			fi
		fi
	done
}

#执行脚本，确保脚本中的语句错误不影响aadm的运行
evalscriptfunction() {
	local temp_aad_trace=""
	if [[ "${KEEP_AAD_TRACE}" ]]; then
		temp_aad_trace="${AAD_TRACE}"
		AAD_TRACE="${KEEP_AAD_TRACE}"
	fi
	export BASELINENO=$LINENO
	eval "$1"
	local ret=$?
	if [[ "${KEEP_AAD_TRACE}" ]]; then
		AAD_TRACE="${temp_aad_trace}"
	fi
	return $ret
}

#执行脚本，将返回值写入指定文件
evalscript() {
	evalscriptfunction "$1" 2>&1
	echo $?>"$2"
}

evalcommand() {
	gen_id
	local forceflag=""
	if [[ "$1" == "FORCE_OUTPUT" ]]; then
		forceflag="_"
		shift
	fi
	local script="$1"
	local surfix="$2"
	local filter="$3"
	local tmpretfile="/tmp/aad.$id.ret"
	local tmpoutfile="/tmp/aad.$id.out"
	if [[ -e "$tmpretfile" ]]; then
		rm "$tmpretfile"
	fi
	if [[ -e "$tmpoutfile" ]]; then
		rm "$tmpoutfile"
	fi
	touch "$tmpoutfile"
	evalscript "$script" "$tmpretfile" >"$tmpoutfile" <&0 &
	local count=1
	local lastline=""
	local running="."
	while [[ "$running" ]]
	do
		if [[ -e "$tmpretfile" ]]; then
			running=""
		fi
		local lines=$(tail -n +$count "$tmpoutfile")
		if [[ "${lines}" && "${lines}." != "${lastline}" ]]; then
			lines=(`encode_text "${lines}"`)
			local n=0
			for line in ${lines[@]}
			do
				line=`decode "${line}"`
				if [[ $n == 0 ]]; then
					n=1
				else
					if [[ "${filter}" ]]; then
						trace $forceflag$tl_proc "${lastline/%./${surfix}}" | $filter
					else
						trace $forceflag$tl_proc "${lastline/%./${surfix}}"
					fi
					count=`expr ${count} + 1`
				fi
				lastline="${line}."
			done
		else
			usleep 10000
		fi
	done
	if [[ "${lastline}" ]]; then
		if [[ "${filter}" ]]; then
			trace $forceflag$tl_proc "${lastline/%./${surfix}}" | $filter
		else
			trace $forceflag$tl_proc "${lastline/%./${surfix}}"
		fi
	fi
	local eval_script_return=`cat "$tmpretfile"`
	if [[ ! "$eval_script_return" =~ $pt_number ]]; then
		eval_script_return=108
	fi
	rm "$tmpoutfile"
	rm "$tmpretfile"
	return $eval_script_return
}

evalcmd() {
	#每行末尾追加一个字符，防止与结束标记混淆
	#  -结尾，分割线
	#  ,结尾，脚本
	#  .结尾，运行输出
	#  ]结尾，运行返回值
	#  !结尾，错误输出 -- 未实现
	local script=`nl -ba -s ": " -w 3 <<< "$1" | sed -e "s/$/,/g"`
	trace $tl_proc "------ script of $2 ------${newline}${script}" >>"$3"
	trace $tl_proc "------ output of $2 ------" >>"$3"
	#执行脚本
	evalcommand FORCE_OUTPUT "$1" '.' >>"$3"
	local eval_script_return=$?
	trace $tl_proc "------  end  of $2  ------" >>"$3"
	#输出结束标记，返回值
	trace _$tl_proc "------ $2 return [${eval_script_return}]">>"$3"
}

#显示输出文件
# $4 输出分类控制标记 e代表错误输出 i代表信息 s代表脚本 o代表标准输出
#输出内容
#  -结尾，分割线
#  ,结尾，脚本
#  .结尾，运行输出
#  !结尾，错误输出
#  ]结尾，运行返回值
pt_command_error="$0:( .*:)? line [0-9]+:( .*:)? .*" 
tailog() {
	local feiso="$3"
	if [[ "${feiso}" == "" ]]; then
		feiso="eiso"
	fi
	local ret=0
	local eof="return \[[0-9]+\]$"
	local count=1
	local all=""
	local lastlines=""
	local lines=""
	while [[ -e "$1" && "${eof}" != "" ]]
	do
		lines=$(tail -n +${count} "$1")
		if [[ "${lines}" && "${lines}" != "${lastline}" ]]; then
			lines=(`encode_text "${lines}"`)
			for line in ${lines[@]}
			do
				line=`decode "${line}"`
				if [[ "${line}" =~ $eof ]]; then
					if [[ "${feiso}" == *i* ]]; then
						trace $tl_proc "${line}"
					fi
					all="${all}${newline}${line}"
					line=${line%]*}
					line=${line##*[}
					ret=${line}
					eof=""
				else
					local linetype=""
					if [[ "${line}" == *! ]]; then
						line=${line%!}      #去除追加标记
						linetype="error"
						if [[ "${feiso}" != *e* ]]; then
							linetype=""
						fi
					elif [[ "${line}" == *, ]]; then
						line=${line%,}      #去除追加标记
						linetype="script"
						if [[ "${feiso}" != *s* ]]; then
							linetype=""
						fi
					elif [[ "${line}" == *. ]]; then
						line=${line%.}      #去除追加标记
						linetype="output"
						if [[ "${feiso}" != *o* ]]; then
							linetype=""
						fi
						if [[ "${line}" =~ $pt_command_error ]]; then
							line="ERROR: ${line}"
						fi
					elif [[ "${line}" == *- ]]; then
						linetype="info"
						if [[ "${feiso}" != *i* ]]; then
							linetype=""
						fi
					else
						lastline="${line}"
						echo "${line} ......  行未完"
						break  #不完整的行
					fi
					if [[ "${linetype}" != "" ]]; then
						all="${all}${newline}${line}"
						trace $tl_proc "${line}"
					fi
					count=`expr ${count} + 1`
				fi
			done
		else
			usleep 100000
		fi
	done
	if [[ "$2" ]]; then
		echo "${all}" >> "$2"
	fi
	trace V "tailog returned ${ret}. $1"
	return $ret
}

#执行命令字符串
execute() {
	local cmdscript=`value "$1"`
	local cmdkey="$2"
	local output="$3"
	local feiso="$4"
	
	KEEP_AAD_TRACE="${AAD_TRACE}"
	AAD_TRACE="`sed -e "s/[${AAD_CMD}]//g" <<< "${AAD_TRACE}"`${AAD_CMD}"
	trace $tl_detail "before execute ${cmdkey}调整设置 AAD_TRACE=${AAD_TRACE}"

	gen_id
	local tempoutputfile="${output}.${id}.tmp"
	touch "${tempoutputfile}"
	trace $tl_detail "开始后台执行命令${cmdkey}"
	evalcmd "${cmdscript}" "${cmdkey}" "${tempoutputfile}" <&0 &
	#ps -ef | grep "tail -F " | grep "${tempoutputfile}" | grep -v " grep " | awk '{print $2}' | xargs nohup kill -9
	#等待脚本执行结束，逐行显示执行过程，输出完整内容到指定日志文件
	trace $tl_detail "开始显示命令${cmdkey}输出"
	tailog "${tempoutputfile}" "${output}" "${feiso}"
	local ret=$?
	rm "${tempoutputfile}"
	trace $tl_detail "命令${cmdkey}输出结束"
	
	trace $tl_detail "after execute ${cmdkey}恢复设置 AAD_TRACE=${KEEP_AAD_TRACE}"
	AAD_TRACE="${KEEP_AAD_TRACE}"
	
	return $ret
}

#执行通过变量定义的命令
call() {
	local cmdkey="$1"
	local outputfile="$2"

	local cmdname="$""{${cmdkey}""_name}"
	cmdname="`eval echo "${cmdname}"`"
	if [[ "${cmdname}" == "" ]]; then
		cmdname="${cmdkey}"
	fi
	trace $tl_status "${ip} ${host} ${agent} ${cmdname}"

	local cmdscript="@{$cmdkey}"
	execute "${cmdscript}" "$cmdkey" "${outputfile}"
	return $?
}

#上传文件
expect_scp_put() {
	local LOGIN="$1"
	local PASSWORD="$2"
	local LOCALFILE="$3"
	local REMOTEFILE="$4"
	expect -c "
		spawn scp ${LOCALFILE} ${LOGIN}:${REMOTEFILE}
		expect {
			timeout { exp_continue }
			\"yes/no\" { send \"yes\\n\"; exp_continue }
			\"assword:\" { send \"${PASSWORD}\\n\"}
		}
		expect {
			timeout { exp_continue }
			\"assword:\" { send_user \"\\n密码错误\\n\"; exit 111 }
			\"100%\" { sleep 0.1; interact }
			eof { catch wait retval; exit [lindex $""retval 3] }
		}
	"
	return $?
}

#下载文件
expect_scp_get() {
	local LOGIN="$1"
	local PASSWORD="$2"
	local LOCALFILE="$3"
	local REMOTEFILE="$4"
	expect -c "
		spawn scp ${LOGIN}:${REMOTEFILE} ${LOCALFILE}
		expect {
			timeout { exp_continue }
			\"yes/no\" { send \"yes\\n\"; exp_continue }
			\"assword:\" { send \"${PASSWORD}\\n\"}
		}
		expect {
			timeout { exp_continue }
			\"assword:\" { send_user \"\\n密码错误\\n\"; exit 111 }
			\"100%\" { sleep 0.1; interact }
			eof { catch wait retval; exit [lindex $""retval 3] }
		}
	"
	return $?
}

#执行远程命令
expect_ssh_cmd() {
	local LOGIN="$1"
	local PASSWORD="$2"
	local COMMAND="eval "'\"'"$3"'\"'"; exit $""?"
	local INTERACT="$4"
	local expscript="
		set prompt \"(%|#|\\\\$|>) $\"
		catch {set prompt $""env(EXPECT_PROMPT)}
		spawn ssh ${LOGIN}
		expect {
			timeout { exp_continue }
			\"yes/no\" { send \"yes\\n\"; exp_continue }
			\"assword:\" { send \"${PASSWORD}\\n\"}
		}
		expect {
			timeout { exp_continue }
			\"assword:\" { send_user \"\\n密码错误\\n\"; exit 111 }
			-re $""prompt { send \"export MOPUSER=${MOPUSER}; export AAD_TRACE=${AAD_TRACE}; ${COMMAND}\\n\" }
		}
		expect {
			timeout { exp_continue }
			${INTERACT}
			eof { catch wait retval; exit [lindex $""retval 3] }
		}
	"
	trace $tl_detail "expect {${expscript}}"
	expect -c "${expscript}"
	local ret=$?
	trace $tl_proc "ssh cmd returned $ret"
	return $ret
}

#连接远程服务器，获取临时工作目录
remote_home="/root/aad.work"
m_connect() {
	local ret=0
	local USERNAME="$1"
	local IP="$2"
	local LOGIN="$1@$2"
	local PASSWORD="$3"
	gen_id
	local aadid=$id
	#获取远程服务器home目录
	trace $tl_proc "获取${LOGIN}远程登录服务器home目录"
	expect_ssh_cmd "${LOGIN}" "${PASSWORD}" "mkdir aad.${aadid}; echo \$\{HOME\}\/aad.${aadid} | tee -i \/tmp\/home_${USERNAME}_${aadid}.txt"
	ret=$?
	if [[ "${ret}" != "0" ]]; then
		#出错退出
		return $ret
	fi
	#接收远程服务器home目录存储文件
	expect_scp_get "${LOGIN}" "${PASSWORD}" "${HOME}/aadlogs/home_${USERNAME}_${IP}_${aadid}.txt" "/tmp/home_${USERNAME}_${aadid}.txt"
	ret=$?
	#删除临时文件
	expect_ssh_cmd "${LOGIN}" "${PASSWORD}" "rm -f \/tmp\/home_${USERNAME}_${aadid}.txt"
	if [[ "${ret}" != "0" ]]; then
		#出错退出
		return $ret
	fi
	remote_home=`cat ${HOME}/aadlogs/home_${USERNAME}_${IP}_${aadid}.txt`
	trace $tl_proc "得到${LOGIN}远程登录服务器home目录：${remote_home}"
	rm "${HOME}/aadlogs/home_${USERNAME}_${IP}_${aadid}.txt"
	return 0
}

#清除远程登录服务器临时工作目录
m_disconnect() {
	local ret=0
	local USERNAME="$1"
	local IP="$2"
	local LOGIN="$1@$2"
	local PASSWORD="$3"
	#获取远程服务器home目录
	trace $tl_proc "清除${LOGIN}远程登录服务器临时目录"
	expect_ssh_cmd "${LOGIN}" "${PASSWORD}" "rm -rf ${remote_home}"
	ret=$?
	if [[ "${ret}" != "0" ]]; then
		#出错退出
		return $ret
	fi
	return 0
}

#更新远程服务器aadm
m_upgrade() {
	local ret=0
	local USERNAME="$1"
	local IP="$2"
	local LOGIN="$1@$2"
	local PASSWORD="$3"
	trace $tl_proc "上传AAD启动脚本到${LOGIN}远程登录服务器"
	#更新aadm文件
	expect_scp_put "${LOGIN}" "${PASSWORD}" ".etc/m" "${remote_home}/.m.start"
	ret=$?
	if [[ "${ret}" != "0" ]]; then
		#出错退出
		return $ret
	fi
	trace $tl_proc "上传AAD任务文件到${LOGIN}远程登录服务器"
	expect_scp_put "${LOGIN}" "${PASSWORD}" "${task}" "${remote_home}/.m.task"
	ret=$?
	if [[ "${ret}" != "0" ]]; then
		#出错退出
		return $ret
	fi
	trace $tl_proc "上传AAD核心到${LOGIN}远程登录服务器"
	#if [[ ! -e "../mu.tar" ]]; then
		tar -cf ../mu.tar m .etc >/dev/null
		ls -l ../mu.tar
	#fi
	expect_scp_put "${LOGIN}" "${PASSWORD}" "../mu.tar" "${remote_home}/.m.tar"
	ret=$?
	if [[ "${ret}" != "0" ]]; then
		#出错退出
		return $ret
	fi
	return 0
}

#启动远程服务器agent部署
m_startup() {
	local USERNAME="$1"
	local IP="$2"
	local LOGIN="$1@$2"
	local PASSWORD="$3"
	local HOST="$4"
	local AGENT="$5"
	trace $tl_proc "启动${LOGIN}远程登录服务器AAD"
	expect_ssh_cmd "${LOGIN}" "${PASSWORD}" "cd ${remote_home}; ./.m.start id=99999 ip=$IP host=$HOST agent=$AGENT" "${m_interact}"
	return $?
}

#更新针对特定部署的环境设置
deploy_setting() {
	#基本部署参数
	local ip="$1"
	local host="$2"
	local agent="$3"
	#以host为key
	local f_host="${host//./_}"
	local f_host="${f_host//-/_}"
	local f_agent=`tr "[A-Z]" "[a-z]" <<< "${agent}"` 
	#设置agent特定变量
	local agent_setting_key="$""{agent_setting_${agent}}"
	local agent_setting_file=`eval echo '"'${agent_setting_key}'"'`
	if [[ -e "${agent_setting_file}" ]]; then
		trace $tl_detail "analyze_setting_file ${agent_setting_file}"
		analyze_setting_file "${agent_setting_file}"
	else
		agent_setting_file=".etc/${agent}.setting.txt"
		if [[ -e "${agent_setting_file}" ]]; then
			trace $tl_detail "analyze_setting_file ${agent_setting_file}"
			analyze_setting_file "${agent_setting_file}"
		else
			trace $tl_warn "没有找到${agent}对应的配置文件"
		fi
	fi
	#host特定变量
	local spsetlines=`env | grep -E "aad_${f_host}__[a-zA-Z0-9_]+="`
	spsetlines=(`encode_text "${spsetlines}"`)
	for line in ${spsetlines[@]}
	do
		line=`decode "${line/aad_${f_host}__/}"`
		if [[ "${line}" ]]; then
			trace $tl_detail "export ${line}"
			export "${line}"
		fi
	done
	#host_agent特定变量
	spsetlines=`env | grep -E "aad_${f_host}_${agent}_[a-zA-Z0-9_]+="`
	spsetlines=(`encode_text "${spsetlines}"`)
	for line in ${spsetlines[@]}
	do
		line=`decode "${line/aad_${f_host}_${agent}_/}"`
		if [[ "${line}" ]]; then
			trace $tl_detail "export ${line}"
			export "${line}"
		fi
	done
	#参数指定变量优先级最高，覆盖最终值
	analyze_setting_line "`arguments`" 
	#启动部署流程
	#password中可能含有特殊字符，作为常量使用容易引起脚本语法的混乱，因此必须作为变量使用
	export password=`value "${password}"`
	export username=`value "${username}"`
}

deploy_mscript() {
	local ret=0
	#密码字符串中的特殊字符处理
	local PASSWORD="${password}"
	PASSWORD="${PASSWORD//\\/\\\\}"
	PASSWORD="${PASSWORD//\"/\\\"}"
	#尝试连接并获取remote home
	trace $tl_status "${ip} ${host} ${agent} 连接服务器"
	trace $tl_info "连接远程服务器${username}@${ip} ${host}"
	m_connect "${username}" "${ip}" "${PASSWORD}"
	ret=$?
	if [[ "${ret}" == "0" ]]; then
		trace $tl_info "连接远程服务器${username}@${ip} ${host}成功"
	else
		trace $tl_fatal "连接远程服务器${username}@${ip} ${host}失败[${ret}]"
		m_disconnect "${username}" "${ip}" "${PASSWORD}" 
		return $ret
	fi
	#更新aadm文件
	trace $tl_status "${ip} ${host} ${agent} 更新部署脚本"
	trace $tl_info "更新远程部署脚本${username}@${ip} ${host}"
	m_upgrade "${username}" "${ip}" "${PASSWORD}"
	ret=$?
	if [[ "${ret}" == "0" ]]; then
		trace $tl_info "更新远程部署脚本${username}@${ip} ${host}成功"
	else
		trace $tl_fatal "更新远程部署脚本${username}@${ip} ${host}失败[${ret}]"
		m_disconnect "${username}" "${ip}" "${PASSWORD}"
		return $ret
	fi
	#启动aadm
	trace $tl_status "${ip} ${host} ${agent} 开始部署"
	trace $tl_info "开启远程部署进程${username}@${ip} ${host} ${agent}"
	m_startup "${username}" "${ip}" "${PASSWORD}" "${host}" "${agent}"
	ret=$?
	if [[ "${ret}" == "0" ]]; then
		trace $tl_info "远程部署进程${username}@${ip} ${host} ${agent}结束"
	else
		trace $tl_fatal "远程部署进程${username}@${ip} ${host} ${agent}失败退出[${ret}]"
		m_disconnect "${username}" "${ip}" "${PASSWORD}"
		return $ret
	fi
	trace $tl_status "${ip} ${host} ${agent} 清理临时文件"
	trace $tl_info "清除远程服务器临时文件${username}@${ip} ${host}"
	m_disconnect "${username}" "${ip}" "${PASSWORD}"
	trace $tl_info "远程部署进程${username}@${ip} ${host} ${agent}完成返回"
	return $ret
}

#远程部署实施
deploy_mcmd() {
	local outputfile="${HOME}/aadlogs/deploy.${host}.`date +"%Y%m%d"`.log"
 
	trace _$tl_status "${ip} ${host} ${agent} 准备部署" | tee -a -i "${outputfile}"
	
	export MOPUSER=`whoami`
	
	trace _$tl_info "${MOPUSER}在${HOSTIP}准备远程部署${agent}到${host}[${ip}]" | tee -a -i "${outputfile}"
	deploy_setting "${ip}" "${host}" "${agent}"
	
	local s="${MOPUSER}在${HOSTIP}以${username}的身份远程部署${agent}到${host}[${ip}]"
	trace _$tl_info "${s}开始" | tee -a -i "${outputfile}"
	
	execute "deploy_mscript" "${s}" "${outputfile}"
	ret=$?

	if [[ "${ret}" == "0" ]]; then
		trace _$tl_info "${s}完成" | tee -a -i "${outputfile}"
		trace _$tl_status "${ip} ${host} ${agent} 部署完成" | tee -a -i "${outputfile}"
	else
		trace _$tl_error "${s}失败[$ret]" | tee -a -i "${outputfile}"
		trace _$tl_status "${ip} ${host} ${agent} 部署失败[$ret]" | tee -a -i "${outputfile}"
	fi
	return $ret
}

statusfilter() {
	local msg
	while read msg
	do
		if [[ "${msg}" =~ $pt_trace ]]; then
			local olvl="${msg#*] [}"
			local level="${olvl%%] *}"
			if [[ "$level" == *S* ]]; then
				local ns="${msg##* }"
				local status=`grep "${ip} ${host} ${agent}" "${taskstatusfile}" | awk '{printf "%s",$4}'`
				if [[ "${status}" == "" ]]; then
					echo "${ip} ${host} ${agent} ${ns}" >> "${taskstatusfile}"
				else
					sed -i -e "s/${ip} ${host} ${agent} .*/${ip} ${host} ${agent} ${ns}/" "${taskstatusfile}"
				fi
			fi
		fi
		echo "$msg"
	done
}

#远程部署实施
remote_deploy_process() {
	local ret=0

	analyze_taskfile "${task}" #任务设置值
	export task_file_analyzed="${task}"

	if [[ "${host}" == "" ]]; then
		ihk="$""{ip_host_${ip//./_}}"
		host=`eval echo '"'${ihk}'"'`
	fi
	
	if [[ "${host}" == "" ]]; then
		trace $tl_fatal "找不到IP[${ip}]对应的主机名"
		return 101
	else
		if [[ "${agent}" == "" ]]; then
			trace $tl_error "参数中找不到IP[${ip}]对应的部署任务"
			return 101
		fi
	fi
	
	evalcommand "deploy_mcmd" "" "statusfilter"
	ret=$?
	if [[ "${ret}" == "111" ]]; then
		trace $tl_fatal "${ret}: 密码错误"
	elif [[ "${ret}" == "126" ]]; then
		trace $tl_fatal "${ret}: 权限不够"
	elif [[ "${ret}" == "130" ]]; then
		trace $tl_fatal "${ret}: 执行过程被中断"
	fi
	return $ret
}

#本地部署实施
local_deploy_process() {
	local ret=0
	
	analyze_taskfile "${task}" #任务设置值
	export task_file_analyzed="${task}"
	
	if [[ ! "${ip}" =~ $pt_ip || "${host}" == "" || "${agent}" == "" ]]; then
		trace $tl_fatal "参数错误，id=99999代表本地运行main_process"
		return 101
	fi

	local s="${MOPUSER}从${SSH_CONNECTION%% *}以`whoami`的身份在${host}[${ip}]部署${agent}"
	if [[ "${host}" != "${HOSTNAME}" ]]; then
		trace $tl_fatal "${s}失败，服务器名称不符"
		return 121
	fi
	
	trace $tl_info "${s}准备就绪"
	deploy_setting "${ip}" "${host}" "${agent}"
	trace $tl_info "${s}开始执行"
	
	trace $tl_status "${ip} ${host} ${agent} 执行部署"

	execute "${main_process}" "${s}" "${HOME}/aadlogs/command.`date +"%Y%m%d"`.log"
	ret=$?

	if [[ "${ret}" == "0" ]]; then
		trace $tl_info "${s}完成"
	else
		trace $tl_fatal "${s}失败[${ret}]"
	fi
	return $ret
}

#初始化
init() {
	#ps -ef | grep -E "/m($|[ \t])" | grep -v "ps -ef | grep"
	if [[ ! -d "${HOME}/aadlogs" ]]; then
		mkdir "${HOME}/aadlogs"
	fi
	export task="task" #默认处理任务配置目录下的所有任务文件，任务配置目录，缺省为 task
	analyze_setting_line "`arguments`" #参数指定变量优先级最高，多次执行，第一次是为了设置全局值和缺省值，再次执行是为了覆盖最终值
	trace $tl_detail "`echo AAD_TRACE=${AAD_TRACE}`"
	trace $tl_detail "current processes:${newline}`ps -ef | grep -E "/m($|[ \t])" | grep -v "expect -c" | grep -v "ps -ef | grep" | grep -v -E "[0-9]+[ ]+$$[ ]+"`"
	export taskstatusfile="`sed -e "s/[^\/]*$/.&/" <<< "${task}"`"
}
init

analyze_setting_file "./.etc/setting.txt" #设置全局缺省值

analyze_setting_line "`arguments`" #参数指定变量优先级最高，覆盖最终值

if [[ "${id}" == "99999" ]]; then

	local_deploy_process
	exit $?
	
elif [[ "${ip}" =~ $pt_ip ]]; then
	
	remote_deploy_process
	exit $?
	
else

	trace $tl_detail "task=${task}"
	if [[ -d "${task}" ]]; then #task指定的是任务目录
		select_task
	elif [[ -e "${task}" ]]; then #task指定的是任务文件
		analyze_taskfile "${task}" #任务设置值
		export task_file_analyzed="${task}"
		confirm_task
	else
		trace $tl_fatal "找不到指定的任务文件：${task}"
		exit 101
	fi
	exit $?
	
fi


#################################################
#################################################
#                                               #
#                    _ooOoo_                    #
#                   o8888888o                   #
#                   88" . "88                   #
#                   (| -_- |)                   #
#                   O\  =  /O                   #
#                ____/`---'\____                #
#              .'  \\|     |//  `.              #
#             /  \\|||  :  |||//  \             #
#            /  _||||| -:- |||||-  \            #
#            |   | \\\  -  /// |   |            #
#            | \_|  ''\---/''  |   |            #
#            \  .-\__  `-`  ___/-. /            #
#          ___`. .'  /--.--\  `. . __           #
#       ."" '<  `.___\_<|>_/___.'  >'"".        #
#      | | :  `- \`.;`\ _ /`;.`/ - ` : | |      #
#      \  \ `-.   \_ __\ /__ _/   .-` /  /      #
#=======`-.____`-.___\_____/___.-`____.-'=======#
#                    `=---='                    #
#^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^#
# 一切众生皆具如来智慧德相 只因妄想执着不能证得 #
#################################################
# # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # #

exit 0

