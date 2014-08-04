#!/bin/bash
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# SHERIFF-FW
# autor: Dorival Junior (dorivaljunior@gmail.com)
# requer arquivo sheriff-fw.conf, demais arquivos texto e ipcalc
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
VERSAO="12.04 em 27 de marco de 2012"

LEITURA_VARIAVEIS_BASICAS()
{
	IFCONFIG=$(cat $ARQ_CONFIG | grep -v ^# | grep . | grep IFCONFIG | cut -d'=' -f2)
	IPCALC=$(cat $ARQ_CONFIG | grep -v ^# | grep . | grep IPCALC | cut -d'=' -f2)
	LOG=$( cat $ARQ_CONFIG | grep -v ^# | grep . | grep ARQUIVO_LOG | cut -d'=' -f2 )
	DATA=$(/bin/date)

}

DESCOBRE_IP()
{
        Z=$($IFCONFIG -a $1 2> /dev/null | sed s/end.:/addr:/ | awk /'inet addr:'/ | sed 's/.*addr://' | awk '{print $1}')
	if [ -n "$Z" ]; then echo $Z; fi
}


DESCOBRE_REDE()
{
# requer o DESCOBRE_IP()
	MASCARA=$($IFCONFIG -a $1 2> /dev/null | sed s/Masc:/Mask:/ | awk /'Mask:'/ | sed 's/.*Mask://' )
	IP=$(DESCOBRE_IP $1)
	if [ -n "$IP" ]; then
		IP_DA_REDE=$($IPCALC $IP $MASCARA | grep Network | awk '{print $2}' ) 
		if [ -n "$IP_DA_REDE" ]; then echo $IP_DA_REDE; fi
	fi
}


VERIFICA_SE_IP_EXTERNO_MUDOU() #executa isolado, sem chamar nenhuma outra funcao antes
{
	LEITURA_VARIAVEIS_BASICAS #leitura de variaveis basicas
	PE=$(cat $ARQ_CONFIG | grep -v ^# | grep . | grep PLACAS_EXTERNAS | cut -d'=' -f2)
	for Y in $PE; do
		X=$( echo $Y | sed s/:/_/g )
		RE[$X]=$( DESCOBRE_REDE `echo $X | sed "s/_/:/g"` )
		if [ -z ${RE[$X]} ]; then # se nao tem rede, indica que eh P-a-P
			IP_ATUAL[$X]=$( DESCOBRE_IP `echo $X | sed "s/_/:/g"` )
			ULTIMO_IP_CONFIGURADO=$( cat $REG_IP | grep $X | cut -d":" -f3 )
			if [ "$DEPURADOR" = "y" ]; then
				echo ""
				echo "   Ultimo IP configurado...($X): $ULTIMO_IP_CONFIGURADO"
				echo "   IP atual................($X): ${IP_ATUAL[$X]}"
				echo ""
				echo "   Em caso de diferenca entre os dois IPs ou ausencia de IP atual, o firewall sera re-executado automaticamente."
				echo "   Verifique o resultado em $LOG"
				echo ""
			fi
			if [ "$ULTIMO_IP_CONFIGURADO" != "${IP_ATUAL[$X]}" -o -z "${IP_ATUAL[$X]}" ]; then 
				echo "********* $DATA: Detectada diferenca de IP externo ou IP inexistente para a interface $X... ******* " >> $LOG
				$0 start
			else
				echo "******* $DATA: IP externo($X) sem alteracao *******" >> $LOG
			fi
		fi
	done
}


TESTA_ARQ_E_CONT()
{
# retorno o NOME do arquivo
	ARQ=$( cat $ARQ_CONFIG | grep -v ^# | grep . | grep $1 | cut -d'=' -f2 ) #localizando nome do arquivo
	CONT=$( cat $ARQ | grep -v ^# | grep . ) #pegando conteudo do arquivo

	if [ -n "$ARQ" -a -n "$CONT" ]; then echo $ARQ; fi
}


PEGA_CONTEUDO()
{
# retorna o CONTEUDO do arquivo
	ARQ=$( cat $ARQ_CONFIG | grep -v ^# | grep . | grep $1 | cut -d'=' -f2 ) #localizando nome do arquivo
	CONT=$( cat $ARQ | grep -v ^# | grep . | tr -s [:blank:] % ) #pegando conteudo do arquivo
	if [ -n "$CONT" ]; then
		echo $CONT
	fi
}


PEGA_CONTEUDO_COLUNA1()
{
# retorna o CONTEUDO do arquivo
	ARQ=$( cat $ARQ_CONFIG | grep -v ^# | grep . | grep $1 | cut -d'=' -f2 ) #localizando nome do arquivo
	CONT=$( cat $ARQ | grep -v ^# | grep . | awk '{print $1}' ) #pegando conteudo do arquivo
	if [ -n "$CONT" ]; then
		echo $CONT
	fi
}



LEITURA_DE_VARIAVEIS()
	{
#	DEPURADOR=$(cat $ARQ_CONFIG | grep -v ^# | grep . | grep MODO_DEPURADOR | cut -d'=' -f2)

	LEITURA_VARIAVEIS_BASICAS

	if [ "$DEPURADOR" = "y" ]
	then 
		clear
		echo "SHERIFF Firewall, versao $VERSAO"
		echo
		echo "-=-=-=--=-=| INICIANDO EM MODO DEPURADOR |=-=-=-=-=-"
		echo
	fi

	IPTABLES=$(cat $ARQ_CONFIG | grep -v ^# | grep . | grep IPTABLES | cut -d'=' -f2)

	TRANSPARENTE=$(cat $ARQ_CONFIG | grep -v ^# | grep . | grep TRANSPARENTE | cut -d'=' -f2)

	PORTAS_PARA_PROXY=$( cat $ARQ_CONFIG | grep -v ^# | grep . | grep PORTAS_PARA_PROXY | cut -d'=' -f2 )

	CONECTIVIDADE=$(cat $ARQ_CONFIG | grep -v ^# | grep . | grep CONECTIVIDADE | cut -d'=' -f2) 

	DIOPS=$(cat $ARQ_CONFIG | grep -v ^# | grep . | grep DIOPS | cut -d'=' -f2) 

	BLOQUEIO_ULTRASURF=$(cat $ARQ_CONFIG | grep -v ^# | grep . | grep BLOQUEIO_ULTRASURF | cut -d'=' -f2)

	BLOQUEIO_FACEBOOK=$(cat $ARQ_CONFIG | grep -v ^# | grep . | grep BLOQUEIO_FACEBOOK | cut -d'=' -f2)

	IP_EXTERNO_RECEBE_PING=$( cat $ARQ_CONFIG | grep -v ^# | grep . | grep IP_EXTERNO_RECEBE_PING | cut -d'=' -f2 )
	IP_INTERNO_RECEBE_PING=$( cat $ARQ_CONFIG | grep -v ^# | grep . | grep IP_INTERNO_RECEBE_PING | cut -d'=' -f2 )

	BLOQUEIO_COMUNICACAO_ENTRE_REDES_INTERNAS=$( cat $ARQ_CONFIG | grep -v ^# | grep . | grep BLOQUEIO_COMUNICACAO_ENTRE_REDES_INTERNAS | cut -d'=' -f2 )

	PORTAS_ALTAS=$( cat $ARQ_CONFIG | grep -v ^# | grep . | grep PORTAS_ALTAS | cut -d'=' -f2 )

	REDIRECIONAMENTOS=$( TESTA_ARQ_E_CONT "ARQUIVO_REDIRECIONAMENTO")

	if [ "$DEPURADOR" = "y" ]; then
		echo "Data: $DATA"
		echo "Arquivo de LOG: $LOG"
		echo "Localizacao do iptables: $IPTABLES"
		echo "Localizacao do ifconfig: $IFCONFIG"
		echo -n "Uso de proxy transparente: "
		if [ -n "$PORTAS_PARA_PROXY" ]; then 
			echo $TRANSPARENTE
		else
			echo "NENHUMA PORTA ESPECIFICADA"
		fi
		echo "Portas redirecionadas para proxy: $PORTAS_PARA_PROXY"
		echo "Regras de conectividade social: $CONECTIVIDADE"
		echo "Regras de DIOPS: $DIOPS"
		echo "Bloqueio de ultrasurf: $BLOQUEIO_ULTRASURF"
		echo "Bloqueio de facebook: $BLOQUEIO_FACEBOOK"
		echo "IP externo recebe ping: $IP_EXTERNO_RECEBE_PING"
		echo "IP interno recebe ping: $IP_INTERNO_RECEBE_PING"
		echo "Bloqueio de comunicacao entre as redes internas: $BLOQUEIO_COMUNICACAO_ENTRE_REDES_INTERNAS"
		echo "Portas altas: $PORTAS_ALTAS"
		echo -n "Arquivo de redirecionamento: "
		if [ -n "$REDIRECIONAMENTOS" ]; then
			echo $REDIRECIONAMENTOS
		else
			echo "NENHUM REDIRECIONAMENTO INFORMADO ou ARQUIVO INEXISTENTE"
		fi
	fi

	rm -rf $REG_IP 2> /dev/null

	PLACAS_INTERNAS=$( cat $ARQ_CONFIG | grep -v ^# | grep . | grep PLACAS_INTERNAS | cut -d'=' -f2 )
	for Y in $PLACAS_INTERNAS
	do
		X=$( echo $Y | sed s/:/_/g )
		PLACA_INTERNA[$X]=$( DESCOBRE_IP `echo $X | sed "s/_/:/g"` )
		REDE_INTERNA[$X]=$( DESCOBRE_REDE `echo $X | sed "s/_/:/g"` ) 
		if [ "$DEPURADOR" = "y" ]; then 
			echo "Rede interna [${REDE_INTERNA[$X]}] via [$X] com IP: ${PLACA_INTERNA[$X]}"
		else
			echo "$DATA: rede interna [${REDE_INTERNA[$X]}] via [$X] com IP ${PLACA_INTERNA[$X]}" >> $LOG
		fi
		echo "interna:$X:${PLACA_INTERNA[$X]}:${REDE_INTERNA[$X]}" >> $REG_IP

	done

	PLACAS_EXTERNAS=$( cat $ARQ_CONFIG | grep -v ^# | grep . | grep PLACAS_EXTERNAS | cut -d'=' -f2 )
	for Y in $PLACAS_EXTERNAS
	do
		X=$( echo $Y | sed s/:/_/g )
		PLACA_EXTERNA[$X]=$( DESCOBRE_IP `echo $X | sed "s/_/:/g"` )
		REDE_EXTERNA[$X]=$( DESCOBRE_REDE `echo $X | sed "s/_/:/g"` )
		if [ "$DEPURADOR" = "y" ]; then 
			echo "Rede externa [${REDE_EXTERNA[$X]}] via [$X] com IP: ${PLACA_EXTERNA[$X]}"
		else
			echo "$DATA: rede externa [${REDE_EXTERNA[$X]}] via [$X] com IP ${PLACA_EXTERNA[$X]}" >> $LOG
		fi
		echo "externa:$X:${PLACA_EXTERNA[$X]}:${REDE_EXTERNA[$X]}" >> $REG_IP
	done

	if [ "$DEPURADOR" = "y" ]; then	echo -n "Portas permitidas para repasse originado da rede interna: "; fi
	PORTAS_PERMITIDAS_REPASSE_ORIGEM_INTERNA=$( TESTA_ARQ_E_CONT "PORTAS_PERMITIDAS_REPASSE_ORIGEM_INTERNA")
	if [ -n "$PORTAS_PERMITIDAS_REPASSE_ORIGEM_INTERNA" ]; then
		if [ "$DEPURADOR" = "y" ]; then
			echo $PORTAS_PERMITIDAS_REPASSE_ORIGEM_INTERNA
		else
			echo "$DATA: portas permitidas para repasse origem interna: $PORTAS_PERMITIDAS_REPASSE_ORIGEM_INTERNA" >> $LOG
		fi
	else
		if [ "$DEPURADOR" = "y" ]; then echo "NAO INFORMADO ou ARQUIVO INEXISTENTE"; fi
	fi

	if [ "$DEPURADOR" = "y" ]; then echo -n "Portas permitidas para repasse originado da rede externa: "; fi
	PORTAS_PERMITIDAS_REPASSE_ORIGEM_EXTERNA=$( TESTA_ARQ_E_CONT "PORTAS_PERMITIDAS_REPASSE_ORIGEM_EXTERNA")
	if [ -n "$PORTAS_PERMITIDAS_REPASSE_ORIGEM_EXTERNA" ]; then
		if [ "$DEPURADOR" = "y"]; then
			echo $PORTAS_PERMITIDAS_REPASSE_ORIGEM_EXTERNA
		else
			echo "$DATA: portas permitidas para repasse origem externa: $PORTAS_PERMITIDAS_REPASSE_ORIGEM_EXTERNA" >> $LOG

		fi
	else
		if [ "$DEPURADOR" = "y" ]; then echo "NAO INFORMADO ou ARQUIVO INEXISTENTE"; fi
	fi

	if [ "$DEPURADOR" = "y" ]; then echo -n "Portas permitidas ao proprio firewall de origem interna: "; fi
	PORTAS_PERMITIDAS_FW_ORIGEM_INTERNA=$( TESTA_ARQ_E_CONT "PORTAS_PERMITIDAS_FW_ORIGEM_INTERNA")
	if [ -n "$PORTAS_PERMITIDAS_FW_ORIGEM_INTERNA" ]; then
		if [ "$DEPURADOR" = "y" ]; then
			echo $PORTAS_PERMITIDAS_FW_ORIGEM_INTERNA
		else
			echo "$DATA: portas permitidas ao proprio firewall de origem interna: $PORTAS_PERMITIDAS_FW_ORIGEM_INTERNA" >> $LOG

		fi
	else
		if [ "$DEPURADOR" = "y" ]; then echo "NAO INFORMADO ou ARQUIVO INEXISTENTE"; fi
	fi

	if [ "$DEPURADOR" = "y" ]; then echo -n "Portas permitidas ao proprio firewall de origem externa: "; fi
	PORTAS_PERMITIDAS_FW_ORIGEM_EXTERNA=$( TESTA_ARQ_E_CONT "PORTAS_PERMITIDAS_FW_ORIGEM_EXTERNA")
	if [ -n "$PORTAS_PERMITIDAS_FW_ORIGEM_EXTERNA" ]; then
		if [ "$DEPURADOR" = "y" ]; then
			echo $PORTAS_PERMITIDAS_FW_ORIGEM_EXTERNA
		else
			echo "$DATA: portas permitidas ao proprio firewall de origem externa: $PORTAS_PERMITIDAS_FW_ORIGEM_EXTERNA" >> $LOG

		fi
	else
		if [ "$DEPURADOR" = "y" ]; then echo "NAO INFORMADO ou ARQUIVO INEXISTENTE"; fi
	fi


	if [ "$DEPURADOR" = "y" ]; then echo -n "Regras de liberacao especificas: "; fi
	OUTRAS_LIBERACOES=$( TESTA_ARQ_E_CONT "OUTRAS_LIBERACOES")
	if [ -n "$OUTRAS_LIBERACOES" ]; then
		if [ "$DEPURADOR" = "y" ]; then
			echo $PORTAS_PERMITIDAS_FW_ORIGEM_INTERNA
		else
			 echo "$DATA: regras de liberacao especificas: $OUTRAS_LIBERACOES" >> $LOG
		fi
	else
		if [ "$DEPURADOR" = "y" ]; then echo "NAO INFORMADO ou ARQUIVO INEXISTENTE"; fi
	fi
	
	if [ "$DEPURADOR" = "y" ]; then echo -n "Regras de bloqueio especificas: "; fi
	OUTROS_BLOQUEIOS=$( TESTA_ARQ_E_CONT "OUTROS_BLOQUEIOS")
	if [ -n "$OUTROS_BLOQUEIOS" ]; then
		if [ "$DEPURADOR" = "y" ]; then
			echo $OUTROS_BLOQUEIOS
		else
			 echo "$DATA: regras de bloqueio especificos: $OUTROS_BLOQUEIOS" >> $LOG
		fi
	else
		if [ "$DEPURADOR" = "y" ]; then echo "NAO INFORMADO ou ARQUIVO INEXISTENTE"; fi
	fi

	if [ "$DEPURADOR" = "y" ]; then echo -n "IPs externos totalmente bloqueados para repasse a(s) rede(s) interna(s): "; fi
	IPS_BLOQUEADOS=$( TESTA_ARQ_E_CONT "IPS_BLOQUEADOS")
	if [ -n "$IPS_BLOQUEADOS" ]; then
		if [ "$DEPURADOR" = "y" ]; then
			echo $IPS_BLOQUEADOS
		else
			echo "$DATA: IPs externos totalmente bloqueados para repasse a(s) rede(s) interna(s): $IPS_BLOQUEADOS" >> $LOG
		fi
	else
		if [ "$DEPURADOR" = "y" ]; then echo "NAO INFORMADO ou ARQUIVO INEXISTENTE"; fi
	fi


	if [ "$DEPURADOR" = "y" ]; then echo -n "Sites externos totalmente bloqueados para repasse a(s) rede(s) interna(s): "; fi
	SITES_BLOQUEADOS=$( TESTA_ARQ_E_CONT "SITES_BLOQUEADOS")
	if [ -n "$SITES_BLOQUEADOS" ]; then
		if [ "$DEPURADOR" = "y" ]; then
			echo $SITES_BLOQUEADOS
		else
			echo "$DATA: IPs externos totalmente bloqueados para repasse a(s) rede(s) interna(s): $SITES_BLOQUEADOS" >> $LOG

		fi
	else
		if [ "$DEPURADOR" = "y" ]; then echo "NAO INFORMADO ou ARQUIVO INEXISTENTE"; fi
	fi

	if [ "$DEPURADOR" = "y" ]; then echo -n "IPs externos para acesso sem proxy transparente: "; fi
	NO_PROXY_TRANSP=$( TESTA_ARQ_E_CONT "NO_PROXY_TRANSP")
	if [ -n "$NO_PROXY_TRANSP" ]; then
		if [ "$DEPURADOR" = "y" ]; then
			echo $NO_PROXY_TRANSP
		else
			echo "$DATA: IPs externos para acesso sem proxy transparente: $NO_PROXY_TRANSP" >> $LOG

		fi
		NO_PROXY_TRANSP=$( PEGA_CONTEUDO "NO_PROXY_TRANSP" )
	else
		if [ "$DEPURADOR" = "y" ]; then echo "NAO INFORMADO ou ARQUIVO INEXISTENTE"; fi
	fi

	if [ "$DEPURADOR" = "y" ]; then echo -n "IPs internos com acesso negado a outras redes incluindo internet: "; fi
	SEM_COMUNICAR=$( TESTA_ARQ_E_CONT "SEM_COMUNICAR")
	if [ -n "$SEM_COMUNICAR" ]; then
		if [ "$DEPURADOR" = "y" ]; then
			echo $SEM_COMUNICAR
		else
			echo "$DATA: IPs internos com acesso negado a outras redes incluindo internet: $SEM_COMUNICAR" >> $LOG

		fi
		SEM_COMUNICAR=$( PEGA_CONTEUDO "SEM_COMUNICAR" )
	else
		if [ "$DEPURADOR" = "y" ]; then echo "NAO INFORMADO ou ARQUIVO INEXISTENTE"; fi
	fi

	if [ "$DEPURADOR" = "y" ]; then echo -n "IPs internos com excessao aos bloqueios de IP e portas para internet (ACESSO TOTAL) : "; fi
	GENTE_FINA_INTERNO=$( TESTA_ARQ_E_CONT "GENTE_FINA_INTERNO")
	if [ -n "$GENTE_FINA_INTERNO" ]; then
		if [ "$DEPURADOR" = "y" ]; then
			echo $GENTE_FINA_INTERNO
		else
			echo "$DATA: IPs internos com excessao aos bloqueios de IP e portas para internet (ACESSO TOTAL): $GENTE_FINA_INTERNO" >> $LOG

		fi
		GENTE_FINA_INTERNO=$( PEGA_CONTEUDO "GENTE_FINA_INTERNO" )
	else
		if [ "$DEPURADOR" = "y" ]; then echo "NAO INFORMADO ou ARQUIVO INEXISTENTE"; fi
	fi

	if [ "$DEPURADOR" = "y" ]; then echo -n "IPs que serao excessao aos bloqueios ao proprio firewall : "; fi
	GENTE_FINA_PARA_FW=$( TESTA_ARQ_E_CONT "GENTE_FINA_PARA_FW")
	if [ -n "$GENTE_FINA_PARA_FW" ]; then
		if [ "$DEPURADOR" = "y" ]; then
			echo $GENTE_FINA_PARA_FW
		else
			echo "$DATA: IPs internos com excessao aos bloqueios a maquina firewall: $GENTE_FINA_PARA_FW" >> $LOG

		fi
		GENTE_FINA_PARA_FW=$( PEGA_CONTEUDO "GENTE_FINA_PARA_FW" )
	else
		if [ "$DEPURADOR" = "y" ]; then echo "NAO INFORMADO ou ARQUIVO INEXISTENTE"; fi
	fi
} #fim da leitura de variaveis


DEFINE_DNS()
{
	for I in $PLACAS_EXTERNAS; do
		if [ "$DEPURADOR" = "y" ]; then
			echo "Liberando o firewall para consulta DNS externa"
		else
			echo  "$DATA: Liberando o firewall para consulta DNS externa" >> $LOG
		fi
		# testar a retirada do IP da placa externa
		$IPTABLES -A OUTPUT -p tcp -s ${PLACA_EXTERNA[$I]} --sport $PORTAS_ALTAS -d 0/0 --dport 53 -j ACCEPT
		$IPTABLES -A INPUT -p tcp -d ${PLACA_EXTERNA[$I]} --dport $PORTAS_ALTAS -s 0/0 --sport 53 -j ACCEPT
		$IPTABLES -A OUTPUT -p udp -s ${PLACA_EXTERNA[$I]} --sport $PORTAS_ALTAS -d 0/0 --dport 53 -j ACCEPT
		$IPTABLES -A INPUT -p udp -d ${PLACA_EXTERNA[$I]} --dport $PORTAS_ALTAS -s 0/0 --sport 53 -j ACCEPT
	done
}


REDIRECIONA()
{
	if [ -n "$REDIRECIONAMENTOS" ]; then
		X=$( PEGA_CONTEUDO "ARQUIVO_REDIRECIONAMENTO" )
		if [ -n "$X" ]; then
			for I in $X; do
				IN_P=$( echo $I | cut -d"%" -f1)
				IP_D=$( echo $I | cut -d"%" -f2)
				DS_P=$( echo $I | cut -d"%" -f3)
				M=$( echo $I | cut -d"%" -f4- | sed "s/%/ /g" )
				if [ "$DEPURADOR" = "y" ]; then 
					echo "Redirecionando porta de entrada $IN_P para $IP_D:$DS_P ($M)"
				else
					echo "$DATA: redirecionando porta de entrada $IN_P para $IP_D:$DS_P ($M)" >> $LOG
				fi
				$IPTABLES -t nat -A PREROUTING  -p tcp --dport $IN_P -j DNAT --to $IP_D:$DS_P
				$IPTABLES -t nat -A POSTROUTING -p tcp --dport $DS_P -d $IP_D -j MASQUERADE
				$IPTABLES -A FORWARD -p tcp -d $IP_D --dport $DS_P -j ACCEPT
				$IPTABLES -A FORWARD -p tcp -s $IP_D --sport $DS_P -j ACCEPT
			done
		fi
	fi
}

LIMPO()
{
	if [ "$DEPURADOR" = "y" ]; then 
		echo "Definindo todas politicas como ACCEPT"
	else
		echo "$DATA: definindo todas as politicas como ACCEPT" >> $LOG
	fi
	$IPTABLES -P INPUT ACCEPT
	$IPTABLES -P OUTPUT ACCEPT
	$IPTABLES -P FORWARD ACCEPT

	if [ "$DEPURADOR" = "y" ]; then echo "Liberando loopback"; fi
	$IPTABLES -A INPUT -d 127.0.0.1 -j ACCEPT
	$IPTABLES -A OUTPUT -d 127.0.0.1 -j ACCEPT

	for X in $PLACAS_INTERNAS; do
		if [ "$DEPURADOR" = "y" ]; then 
			echo "Liberando forward entre ${REDE_INTERNA[$X]} e qualquer lugar."
		else
			echo "$DATA: Liberando forward entre ${REDE_INTERNA[$X]} e qualquer lugar." >> $LOG
		fi
			$IPTABLES -A FORWARD -s ${REDE_INTERNA[$X]} -d 0/0 -j ACCEPT
			$IPTABLES -A FORWARD -d ${REDE_INTERNA[$X]} -s 0/0 -j ACCEPT
	done
	#obs.: a regra de NAT esta numa funcao propria
}


NAT()  
{
	if [ "$DEPURADOR" = "y" ]; then 
		echo "Ativando repasse entre redes no /proc/sys/net/ipv4/ip_forward."
	else
		echo "$DATA: ativando repasse entre redes no /proc/sys/net/ipv4/ip_forward" >> $LOG
	fi
	echo 1 > /proc/sys/net/ipv4/ip_forward

	for Y in $PLACAS_INTERNAS; do
		for X in $PLACAS_EXTERNAS; do
			if [ "$DEPURADOR" = "y" ]; then 
				echo "Fazendo mascaramento entre origem ${REDE_INTERNA[$Y]} com saida para $X"
			else
				echo "$DATA: fazendo mascaramento entre origem ${REDE_INTERNA[$Y]} com saida para $X" >> $LOG
			fi
			$IPTABLES -t nat -A POSTROUTING -s ${REDE_INTERNA[$Y]} -o $X -j MASQUERADE
		done
	done
}

BLOQUEIA_COMUNICACAO_ENTRE_REDES_INTERNAS()
{
	if [ "$BLOQUEIO_COMUNICACAO_ENTRE_REDES_INTERNAS" = "y" ]; then
		ACAO="DROP"
		S="NEGADO"
	else
		ACAO="ACCEPT"
			S="PERMITIDO"
	fi

	for I in $PLACAS_INTERNAS; do
		for N in $PLACAS_INTERNAS; do
			if [ "$I" != "$N" ]; then
				if [ "$DEPURADOR" = "y" ]; then 
					echo "Definindo a comunicacao entre ${REDE_INTERNA[$I]} e ${REDE_INTERNA[$N]} como $S"
					echo "Definindo acesso do gateway ${REDE_INTERNA[$N]} para a rede ${REDE_INTERNA[$I]} como $S"
				else
					echo "$DATA: definindo a comunicacao entre ${REDE_INTERNA[$I]} e ${REDE_INTERNA[$N]} como $S" >> $LOG
					echo "$DATA: definindo acesso ao gateway ${REDE_INTERNA[$N]} para a rede ${REDE_INTERNA[$I]} como $S" >> $LOG

				fi
				$IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -d ${REDE_INTERNA[$N]} -j $ACAO
				$IPTABLES -A FORWARD -s ${REDE_INTERNA[$N]} -d ${REDE_INTERNA[$I]} -j $ACAO

				$IPTABLES -A INPUT -s ${REDE_INTERNA[$I]} -d ${PLACA_INTERNA[$N]} -j $ACAO
				$IPTABLES -A OUTPUT -d ${REDE_INTERNA[$I]} -d ${PLACA_INTERNA[$N]} -j $ACAO
			fi
		done
	done
}


INICIANDO()
{
	echo -ne '\033[11;200]\033[10;900]\a'
	if [ "$DEPURADOR" = "y" ]; then 
		echo -e '\033[33;1m=-=-=-=-=-=-=-=> INICIANDO FIREWALL:\033[m'
		echo "Iniciando SHERIFF Firewall ($DATA) em modo depurador" >> /var/log/messages

	else
		echo "**************** INICIANDO FIREWALL ($DATA) ***********" >> $LOG
	fi
	echo -e '\033[33m'
	echo -ne '\033[11;200]\033[10;900]\a'
}


LIMPANDO_REGRAS()
{
	if [ "$DEPURADOR" = "y" ]; then 
		echo "Limpando regras existentes..."
	else
		echo "$DATA: limpando regras existentes" >> $LOG
	fi
	$IPTABLES -F
	$IPTABLES -F -t nat
}


DEFININDO_POLITICAS_PRINCIPAIS()
{
	if [ "$DEPURADOR" = "y" ]; then 
		echo "Definindo politica restritiva"
	else
		echo "$DATA: definindo politica restritiva" >> $LOG
	fi
	$IPTABLES -P INPUT DROP
	$IPTABLES -P OUTPUT DROP
	$IPTABLES -P FORWARD DROP
}


PARANDO_CONEXOES()
{
	if [ "$DEPURADOR" = "y" ]; then 
		echo "Parando conexoes"
	else
		echo "$DATA: parando conexoes" >> $LOG
	fi
	$IPTABLES -P INPUT DROP
	$IPTABLES -P OUTPUT DROP
	$IPTABLES -P FORWARD DROP
}


ESTADO_DE_CONEXAO()
{
	if [ "$DEPURADOR" = "y" ]; then
		echo "Aplicando diretivas de seguranca de estado de conexao para ENTRADAS no firewall e REPASSE de conexoes"
	else
		echo "$DATA: Aplicando diretivas de seguranca de estado de conexao para ENTRADAS no firewall e REPASSE de conexoes" >> $LOG
	fi
	
	if [ "$DEPURADOR" = "y" ]; then echo "   Permitindo entrada de pacotes relacionados ou conexoes estabelecidas"; fi
	$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

	if [ "$DEPURADOR" = "y" ]; then	echo "   Permitindo repasse de pacotes relacionados ou conexoes estabelecidas"; fi
	$IPTABLES -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

	if [ "$DEPURADOR" = "y" ]; then	echo "   Permitindo saida de pacotes relacionados ou conexoes estabelecidas"; fi
	$IPTABLES -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

	if [ "$DEPURADOR" = "y" ]; then	echo "   Bloqueando entrada de conexoes invalidas"; fi
	$IPTABLES -A INPUT -m state --state INVALID -j DROP

	if [ "$DEPURADOR" = "y" ]; then	echo "   Bloqueando repasse de conexoes invalidas"; fi
	$IPTABLES -A FORWARD -m state --state INVALID -j DROP
}


PROTECAO_CONTRA_ATAQUES()
{
	if [ "$DEPURADOR" = "y" ]; then 
		echo "Aplicando protecoes contra ataques comuns"
	else
		echo "$DATA: Aplicando protecoes contra ataques comuns" >> $LOG
	fi

	if [ "$DEPURADOR" = "y" ]; then echo "   Protecao contra IP Spoofing"; fi
	echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter
	echo "1" > /proc/sys/net/ipv4/conf/default/rp_filter

 	if [ "$DEPURADOR" = "y" ]; then echo "   Protecao contra pacotes de origem suspeita"; fi
	echo "1" > /proc/sys/net/ipv4/conf/all/log_martians

	if [ "$DEPURADOR" = "y" ]; then echo "   Protecao contra Syn-flood e DOS"; fi
	$IPTABLES -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT
	echo "1" > /proc/sys/net/ipv4/tcp_syncookies

	if [ "$DEPURADOR" = "y" ]; then echo "   Pprotecao para rejeitar requisicoes ICMP ECHO"; fi
	echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

	if [ "$DEPURADOR" = "y" ]; then echo "   Protecao para ignorar mensagens falsas de icmp_error_responses"; fi
	echo "1" > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

	if [ "$DEPURADOR" = "y" ]; then echo "   Protecao contra Man-in-the-Middle"; fi
	echo "1" > /proc/sys/net/ipv4/conf/all/accept_redirects

	if [ "$DEPURADOR" = "y" ]; then echo "   Protecao contra scanners de porta"; fi
	$IPTABLES -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
	$IPTABLES -A INPUT -p tcp --tcp-flags ALL SYN,ACK -j LOG --log-level debug --log-prefix "*** DROP PortScanner:"
	$IPTABLES -A INPUT -p tcp --tcp-flags ALL SYN,ACK -j DROP
}


PERMISSAO_DE_LOOPBACK()
{
	# REGRAS BASICAS DO GATEWAY (DEVE VIR APOS DEFINICAO DE BLOQUEIOS DE INPUT E FORWARD DA REDE INTERNA)
	if [ "$DEPURADOR" = "y" ]; then 
		echo "Liberando loopback"
	else
		echo "$DATA: liberando loopback" >> $LOG
	fi
	$IPTABLES -A INPUT -d 127.0.0.1 -j ACCEPT
	$IPTABLES -A OUTPUT -d 127.0.0.1 -j ACCEPT
}


PING()
{
	if [ "$IP_INTERNO_RECEBE_PING" = "y" ]; then
		ACAO="ACCEPT"
		PINGFOI="LIBERADO"
	else
		ACAO="REJECT"
		PINGFOI="BLOQUEADO"
	fi

	for X in $PLACAS_INTERNAS; do
		if [ "$DEPURADOR" = "y" ]; then 
			echo "O ping para o IP ${PLACA_INTERNA[$X]} foi $PINGFOI"
		else
			echo "$DATA: o ping para o IP ${PLACA_INTERNA[$X]} foi $PINGFOI" >> $LOG
		fi
		for TIPO in 0 3 8 11; do
			$IPTABLES -A INPUT -p icmp -s 0/0 -d ${PLACA_INTERNA[$X]} --icmp-type $TIPO -j $ACAO
			$IPTABLES -A OUTPUT -p icmp -s ${PLACA_INTERNA[$X]} -d 0/0 --icmp-type $TIPO -j $ACAO
		done
	done

	if [ "$IP_EXTERNO_RECEBE_PING" = "y" ]; then
		ACAO="ACCEPT"
		PINGFOI="LIBERADO"
	else
		ACAO="REJECT"
		PINGFOI="BLOQUEADO"
	fi

	for X in $PLACAS_EXTERNAS; do
		if [ "$DEPURADOR" = "y" ]; then
			echo "O ping para o IP ${PLACA_EXTERNA[$X]} foi $PINGFOI"
		else
			echo "$DATA: o ping para o IP ${PLACA_EXTERNA[$X]} foi $PINGFOI" >> $LOG
		fi
		for TIPO in 0 3 8 11; do
			$IPTABLES -A INPUT -p icmp -s 0/0 -d ${PLACA_EXTERNA[$X]} --icmp-type $TIPO -j $ACAO
			$IPTABLES -A OUTPUT -p icmp -s ${PLACA_EXTERNA[$X]} -d 0/0 --icmp-type $TIPO -j $ACAO
		done
	done
}


BLOQUEIO_DE_COMUNICACAO()
{
	if [ "$DEPURADOR" = "y" ]; then echo "Bloqueio de comunicacao com qualquer lugar:"; fi
	if [ -n "$SEM_COMUNICAR" ]; then
		for X in $SEM_COMUNICAR; do
			if [ "$DEPURADOR" = "y" ]; then
		                echo "   Bloqueando a comunicacao entre o IP $X e qualquer local"
			else
				echo "$DATA: bloqueando a comunicacao entre o IP $X e qualquer local" >> $LOG
			fi
	                $IPTABLES -A INPUT -s $X -j DROP
	                $IPTABLES -A OUTPUT -s $X -j DROP
	                $IPTABLES -A FORWARD -s $X -d 0/0 -j DROP
	                $IPTABLES -A FORWARD -s 0/0 -d $X -j DROP
	        done
	fi
}


GENTE_FINA_INTERNO()
{
	if [ -n "$GENTE_FINA_INTERNO" ]; then
		if [ "$DEPURADOR" = "y" ]; then echo "Liberando repasse a qualquer rede: (gente fina)"; fi
		for I in $GENTE_FINA_INTERNO; do
			if [ "$DEPURADOR" = "y" ]; then
				echo "   Liberando o IP $I para repasse a qualquer local da internet"
			else
				echo "$DATA: liberando o IP $I para repasse a qualquer local da internet" >> $LOG
			fi
			$IPTABLES -A FORWARD -s $I -d 0/0 -j ACCEPT
			$IPTABLES -A OUTPUT -s $I -d 0/0 -j ACCEPT
			$IPTABLES -A FORWARD -d $I -s 0/0 -j ACCEPT
			$IPTABLES -A OUTPUT -d $I -s 0/0 -j ACCEPT
		done
	fi
}


GENTE_FINA_PARA_FW()
{
	if [ -n "$GENTE_FINA_PARA_FW" ]; then
		if [ "$DEPURADOR" = "y" ]; then echo "Liberando de todos os bloqueios de acesso ao FIREWALL (gente fina input):"; fi
		for I in $GENTE_FINA_PARA_FW; do
			if [ "$DEPURADOR" = "y" ]; then
				echo "   Liberando o IP $I de TODAS as restricoes de acesso ao FIREWALL(input)"
			else
				echo "$DATA: liberando o IP $I de TODAS as restricoes de acesso ao FIREWALL(input)" >> $LOG
			fi
			$IPTABLES -A INPUT -s $I -j ACCEPT
			$IPTABLES -A OUTPUT -d $I -j ACCEPT
		done
	fi
}


LIBERA_PORTA_ENTRADA_FW_ORIGEM_INTERNA()
{
	X=$( PEGA_CONTEUDO "PORTAS_PERMITIDAS_FW_ORIGEM_INTERNA"  )
	if [ -n "$PORTAS_PERMITIDAS_FW_ORIGEM_INTERNA" -a -n "$X" ]; then
		if [ "$DEPURADOR" = "y" ]; then echo "Liberando entrada para o firewall (origem interna):"; fi
		for Z in $X; do
			P=$( echo $Z | cut -d"%" -f1 )
			D=$( echo $Z | cut -d"%" -f2- | sed "s/%/ /g" )
			for I in $PLACAS_INTERNAS; do
				if [ "$DEPURADOR" = "y" ]; then
					echo "   Liberando entrada para firewall(na porta $P) originada de ${REDE_INTERNA[$I]} (para uso de $D)"
					else
						echo "$DATA: Liberando entrada para firewall(na porta $P) originada de ${REDE_INTERNA[$I]} (para uso de $D)" >> $LOG
				fi
				$IPTABLES -A INPUT -s ${REDE_INTERNA[$I]} -p tcp --dport $P -j ACCEPT
				$IPTABLES -A INPUT -s ${REDE_INTERNA[$I]} -p udp --dport $P -j ACCEPT
				$IPTABLES -A OUTPUT -d ${REDE_INTERNA[$I]} -p tcp --sport $P -j ACCEPT
				$IPTABLES -A OUTPUT -d ${REDE_INTERNA[$I]} -p udp --sport $P -j ACCEPT
			done
		done
	fi
}


LIBERA_PORTA_ENTRADA_FW_ORIGEM_GERAL()
{
	X=$( PEGA_CONTEUDO "PORTAS_PERMITIDAS_FW_ORIGEM_EXTERNA" )
	if [ -n "$PORTAS_PERMITIDAS_FW_ORIGEM_EXTERNA" -a -n "$X" ]; then
		if [ "$DEPURADOR" = "y" ]; then echo "Liberando entrada para o firewall (qualquer origem):"; fi
		for Z in $X; do
			P=$( echo $Z | cut -d"%" -f1 )
			D=$( echo $Z | cut -d"%" -f2- | sed "s/%/ /g" )
			if [ "$DEPURADOR" = "y" ]; then
				echo "   Liberando entrada para firewall(na porta $P) originada de qualquer lugar (para uso de $D)"
			else
				echo "$DATA: Liberando entrada para firewall(na porta $P) originada de qualquer lugar (para uso de $D)" >> $LOG
			fi
				$IPTABLES -A INPUT -p tcp --dport $P -j ACCEPT
				$IPTABLES -A INPUT -p udp --dport $P -j ACCEPT
				$IPTABLES -A OUTPUT -p tcp --sport $P -j ACCEPT
				$IPTABLES -A OUTPUT -p udp --sport $P -j ACCEPT
		done
	fi
}


LIBERA_PORTA_REPASSE_ORIGEM_INTERNA()
{
	X=$( PEGA_CONTEUDO "PORTAS_PERMITIDAS_REPASSE_ORIGEM_INTERNA" )
	if [ -n "$PORTAS_PERMITIDAS_REPASSE_ORIGEM_INTERNA" -a -n "$X" ]; then
		if [ "$DEPURADOR" = "y" ]; then echo "Liberando repasse de portas (origem interna):"; fi
		for Z in $X; do
			P=$( echo $Z | cut -d"%" -f1 )
			D=$( echo $Z | cut -d"%" -f2- | sed "s/%/ /g" )
			for I in $PLACAS_INTERNAS; do
				if [ "$DEPURADOR" = "y" ]; then
					echo "   Liberando repasse de pacotes (pela porta $P) originado de ${REDE_INTERNA[$I]} (para uso de $D)"
				else
					echo "$DATA: liberando repasse de pacotes (pela porta $P) originado de ${REDE_INTERNA[$I]} (para uso de $D)" >> $LOG
				fi
				$IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -p tcp --dport $P -j ACCEPT
				$IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -p udp --dport $P -j ACCEPT
				$IPTABLES -A OUTPUT  -p tcp --dport $P -j ACCEPT
				$IPTABLES -A OUTPUT  -p udp --dport $P -j ACCEPT
			done
		done
	fi
}

LIBERA_PORTA_REPASSE_ORIGEM_GERAL()
{
	X=$( PEGA_CONTEUDO "PORTAS_PERMITIDAS_REPASSE_ORIGEM_EXTERNA" )
	if [ -n "$PORTAS_PERMITIDAS_REPASSE_ORIGEM_EXTERNA" -a -n "$X" ]; then
		if [ "$DEPURADOR" = "y" ]; then echo "Liberando portas para repasse (origem externa):"; fi
		for Z in $X; do
			P=$( echo $Z | cut -d"%" -f1 )
			D=$( echo $Z | cut -d"%" -f2- | sed "s/%/ /g" )
			if [ "$DEPURADOR" = "y" ]; then
				echo "   Liberando repasse de pacotes (pela porta $P) originado de qualquer lugar"
			else
				echo "$DATA: liberando repasse de pacotes (pela porta $P) originado de qualquer lugar" >> $LOG
			fi
			$IPTABLES -A FORWARD -p tcp --dport $P -j ACCEPT
			$IPTABLES -A FORWARD -p udp --dport $P -j ACCEPT
		done
	fi
}

OUTRAS_LIBERACOES()
{
	X=$( PEGA_CONTEUDO "OUTRAS_LIBERACOES" )
	if [ -n "$OUTRAS_LIBERACOES" -a -n "$X" ]; then
		if [ "$DEPURADOR" = "y" ]; then echo "Aplicando regras de liberacao especificas:"; fi
		for Z in $X; do
			O=$( echo $Z | cut -d"%" -f1 )
			D=$( echo $Z | cut -d"%" -f2 )
			P=$( echo $Z | cut -d"%" -f3 )
			M=$( echo $Z | cut -d"%" -f4- | sed "s/%/ /g" )
			if [ "$DEPURADOR" = "y" ]; then
				echo "   Liberando repasse de pacotes originado de $O com destino ao IP $D pela porta $P($M)"
			else
				echo "$DATA: Liberando repasse de pacotes originado de $O com destino ao IP $D pela porta $P ($M)" >> $LOG
			fi
			$IPTABLES -A FORWARD -p tcp -s $O -d $D --dport $P -j ACCEPT
			$IPTABLES -A FORWARD -p udp -s $O -d $D --dport $P -j ACCEPT
		done
	fi
}

OUTROS_BLOQUEIOS()
{
	X=$( PEGA_CONTEUDO "OUTROS_BLOQUEIOS" )
	if [ -n "$OUTROS_BLOQUEIOS" -a -n "$X" ]; then
		if [ "$DEPURADOR" = "y" ]; then echo "Aplicando regras de bloqueio especificas:"; fi
		for Z in $X; do
			O=$( echo $Z | cut -d"%" -f1 )
			D=$( echo $Z | cut -d"%" -f2 )
			P=$( echo $Z | cut -d"%" -f3 )
			M=$( echo $Z | cut -d"%" -f4- | sed "s/%/ /g" )
			if [ "$DEPURADOR" = "y" ]; then
				echo "   Bloqueando repasse de pacotes originado de $O com destino ao IP $D pela porta $P($M)"
			else
				echo "$DATA: Bloqueando repasse de pacotes originado de $O com destino ao IP $D pela porta $P ($M)" >> $LOG
			fi
			$IPTABLES -A FORWARD -p tcp -s $O -d $D --dport $P -j DROP
			$IPTABLES -A FORWARD -p udp -s $O -d $D --dport $P -j DROP
		done
	fi
}


BLOQUEIO_DE_IPS()
{
	X=$( PEGA_CONTEUDO "IPS_BLOQUEADOS" )
	if [ -n "$IPS_BLOQUEADOS" -a -n "$X" ]; then
		if [ "$DEPURADOR" = "y" ]; then echo "Bloqueio de acesso a IPs externos:"; fi
		for Z in $X; do
			P=$( echo $Z | cut -d"%" -f1 )
			D=$( echo $Z | cut -d"%" -f2- | sed "s/%/ /g" )
			for I in $PLACAS_INTERNAS; do
				if [ "$DEPURADOR" = "y" ]; then 
					echo "  Bloqueando o acesso de ${REDE_INTERNA[$I]} para o IP $P($D)."
				else
					echo "$DATA: bloqueando o acesso de ${REDE_INTERNA[$I]} para o IP $P($D)" >> $LOG
				fi
                	        $IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -d $P -j DROP
				$IPTABLES -A FORWARD -d ${REDE_INTERNA[$I]} -s $P -j DROP
				done

		done
	fi
}


BLOQUEIO_DE_SITES()
{
	URLS=$( PEGA_CONTEUDO_COLUNA1 "SITES_BLOQUEADOS" )
	if [ -n "SITES_BLOQUEADOS" -a -n "$URLS" ]; then
		if [ "$DEPURADOR" = "y" ]; then echo "Bloqueio de acesso a SITES externos:"; fi
		AUX1="/tmp/sheriff_AUX1"
		AUX2="/tmp/sheriff_AUX2"
		if [ "$DEPURADOR" = "y" ]; then echo "   Identificando IPs... esta tarefa pode demorar um pouco"; fi
		for I in $URLS; do host $I >> $AUX1; done
		sed -n 's/\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}/\nip&\n/gp' $AUX1 | grep ip | sed 's/ip//'| sort | uniq >> $AUX2
		IPS_A_BLOQUEAR=$( cat $AUX2 )
		for Q in $PLACAS_INTERNAS; do
			for R in $IPS_A_BLOQUEAR; do
				if [ "$DEPURADOR" = "y" ]; then
					echo "   Bloqueando o acesso de ${REDE_INTERNA[$Q]} para o IP $R."
				else
					echo "$DATA: bloqueando o acesso de ${REDE_INTERNA[$Q]} para o IP $R." >> $LOG
				fi
				$IPTABLES -A FORWARD -s ${REDE_INTERNA[$Q]} -d $R -j DROP
			done
		done
		rm $AUX1 2> /dev/null
		rm $AUX2 2> /dev/null
	fi
}


CONECTIVIDADE_SOCIAL()
{
	if [ "$CONECTIVIDADE" = "y" ]; then
		if [ "$DEPURADOR" = "y" ]; then echo "Aplicando regras do CONECTIVIDADE SOCIAL:"; fi
		for I in $PLACAS_INTERNAS; do
			if [ "$DEPURADOR" = "y" ]; then
				echo "   Aplicando regras do CONECTIVIDADE SOCIAL para a rede ${REDE_INTERNA[$I]}"
			else
				echo "$DATA: aplicando regras do CONECTIVIDADE SOCIAL para a rede ${REDE_INTERNA[$I]}" >> $LOG
			fi
		        $IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -p tcp -d 200.201.174.207 --dport 80 -j ACCEPT
		        $IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -p tcp -d 200.201.174.204 --dport 80 -j ACCEPT
		        $IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -p tcp -d 200.201.174.204 --dport 2631 -j ACCEPT
	        	$IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -p tcp -d 200.201.0.0/16 -j ACCEPT
		        $IPTABLES -t nat -A PREROUTING -s ${REDE_INTERNA[$I]} -p tcp -d 200.201.0.0/16 -j ACCEPT
		done
	fi
}


DIOPS_ANS()
{
	if [ "$DIOPS" = "y" ]; 	then
		if [ "$DEPURADOR" = "y" ]; then echo "Aplicando regras do DIOPS"; fi
		for I in $PLACAS_INTERNAS; do
			if [ "$DEPURADOR" = "y" ]; then
				echo "   Aplicando regras do DIOPS para a rede ${REDE_INTERNA[$I]}"
			else
				echo "$DATA: aplicando regras do DIOPS para a rede ${REDE_INTERNA[$I]}" >> $LOG
			fi
		        $IPTABLES -t nat -A PREROUTING -p tcp -d 200.255.42.71 -j ACCEPT
	        	$IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -p tcp -d 200.255.42.71 --dport 80 -j ACCEPT
		        $IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -p tcp -d 200.255.42.71 --dport 21 -j ACCEPT
		        $IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -p tcp -d 200.255.42.71 --dport 20000:20020 -j ACCEPT
		        $IPTABLES -t nat -A PREROUTING -s ${REDE_INTERNA[$I]} -p tcp -d 189.21.233.19 -j ACCEPT
	        	$IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -p tcp -d 189.21.233.19 --dport 80 -j ACCEPT
		        $IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -p tcp -d 189.21.233.19 --dport 21 -j ACCEPT
		        $IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -p tcp -d 189.21.233.19 --dport 20000:20020 -j ACCEPT
			$IPTABLES -A FORWARD -s ${REDE_INTERNA[$I]} -p tcp -d 189.21.233.19 --dport 8181 -j ACCEPT
			$IPTABLES -t nat -A PREROUTING -i $I -p tcp --dport 20000:20019 -j ACCEPT
        		$IPTABLES -t nat -A PREROUTING -i $I -p tcp --dport 21 -j ACCEPT
			$IPTABLES -t nat -A PREROUTING -i $I -p tcp --dport 8181 -j ACCEPT
	        	$IPTABLES -t nat -A PREROUTING -p tcp -d 200.255.42.71 -j ACCEPT
	        	$IPTABLES -t nat -A PREROUTING -p tcp -d 189.21.233.19 -j ACCEPT
		done
	fi
}


PROXY_TRANSPARENTE()
{
	if [ "$TRANSPARENTE" = "y" ]; then
		X=$( PEGA_CONTEUDO "NO_PROXY_TRANSP" )
		if [ -n "$NO_PROXY_TRANSP" -a -n "$X" ]; then
	                for SEM_PROXY in $X; do
				A=$( echo $SEM_PROXY | cut -d"%" -f1 )
				B=$( echo $SEM_PROXY | cut -d"%" -f2- | sed "s/%/ /g" )
				for INTERNAS_LANS in $PLACAS_INTERNAS; do
					if [ -n "$PORTAS_PARA_PROXY" ]; then
						$IPTABLES -t nat -A PREROUTING -i $INTERNAS_LANS -p tcp -d ! $A -m multiport --dport $PORTAS_PARA_PROXY -j REDIRECT --to-port 3128
						if [ "$DEPURADOR" = "y" ]; then
							echo "Definindo proxy transparente para $INTERNAS_LANS(portas $PORTAS_PARA_PROXY) com excessao para $A($B)"
						else
							echo "$DATA: definindo proxy transparente para $INTERNAS_LANS(portas $PORTAS_PARA_PROXY) com excessao para $A($B)" >> $LOG
						fi
					else
						$IPTABLES -t nat -A PREROUTING -i $INTERNAS_LANS -p tcp -d ! $A --dport 80 -j REDIRECT --to-port 3128
						if [ "$DEPURADOR" = "y" ]; then
							echo "Definindo proxy transparente para $INTERNAS_LANS(porta 80) com excessao para $A($B)"
						else
							echo "$DATA: definindo proxy transparente para $INTERNAS_LANS(porta 80) com excessao para $A($B)" >> $LOG
						fi
					fi
				done
			done
	        else

			for INTERNAS_LANS in $PLACAS_INTERNAS; do
				if [ "$DEPURADOR" = "y" ]; then
			                echo "Definindo proxy transparente para $INTERNAS_LANS."
				else
					echo "$DATA: Definindo proxy transparente para $INTERNAS_LANS." >> $LOG
				fi
				if [ -n "$PORTAS_PARA_PROXY" ]; then        
					$IPTABLES -t nat -A PREROUTING -i $INTERNAS_LANS -p tcp -m multiport --dport $PORTAS_PARA_PROXY -j REDIRECT --to-port 3128
				else
					$IPTABLES -t nat -A PREROUTING -i $INTERNAS_LANS -p tcp --dport 80 -j REDIRECT --to-port 3128
				fi
				done
	        fi
	fi
}

TESTA_IPS_ANTES_DE_INICIAR()
{
	MENSAGEM="Nao existe IP configurado para a placa externa [$X]. O firewall nao tem como inicializar."
	for X in $PLACAS_EXTERNAS; do
		if [ -z "${PLACA_EXTERNA[$X]}" ]; then
			echo $MENSAGEM
			echo "$DATA: $MENSAGEM" >> $LOG
			exit 0
		fi
	done

	MENSAGEM="Nao existe IP configurado para a placa interna [$X]. O firewall nao tem como inicializar."
	for Y in $PLACAS_INTERNAS; do
		if [ -z "${PLACA_INTERNA[$Y]}" ]; then
			echo $MENSAGEM
			echo "$DATA: $MENSAGEM" >> $LOG
			exit 0
		fi
	done
}


ULTIMAS_REGRAS()
{
	$IPTABLES -A FORWARD -s 0/0 -d 0/0 -j DROP
	$IPTABLES -A INPUT -s 0/0 -d 0/0 -j DROP
}

FINALIZANDO()
{
		echo ""
		echo -e '\033[33;1m===========> REGRAS DE FIREWALL APLICADAS.\033[m'

		echo -ne '\033[11;100]\033[10;1100]\a'

		echo -ne '\033[11;100]\033[10;750]'
		echo ""
		echo "----------------| fim das regras de firewall |---------------------" >> $LOG
}	

AJUDA()
{
	echo "SHERIFF Firewall, by Dorival Junior, dorivaljunior@gmail.com, versao $VERSAO"
	echo ""
	echo "  Opcoes:  start    - executa as regras normalmente segundo os arquivos de configuracao"
	echo "           stop     - para totalmente o firewall, bloqueando todas as conexoes"
	echo "           clean    - executa regras limpas, sem qualquer tipo de bloqueio"
	echo "           ip-test  - verifica se houve alteracao de IP externo(nas conexoes ppp)."
	echo "                      Caso positivo, re-executa o firewall"
	echo
	echo " $0 {opcoes} [-d] para execucao em modo depurador"
}

# inicio da execucao do programa
ARQ_CONFIG="/etc/sheriff-firewall/sheriff-firewall.conf"
REG_IP="/tmp/sheriff_IP"

if [ "$2" = "-d" ]; then DEPURADOR="y"; fi

case "$1" in
	ip-test)
		VERIFICA_SE_IP_EXTERNO_MUDOU
	;;

	stop)
		LEITURA_DE_VARIAVEIS
		LIMPANDO_REGRAS
		PARANDO_CONEXOES
	;;

	start)
		LEITURA_DE_VARIAVEIS
		if [ "$DEPURADOR" = "y" ] 
		then
			echo
			echo -n "Dados carregados. Deseja continuar (s/n)? "
			read OPCAO
			if [ "$OPCAO" = "n" -o "$OPCAO" = "N" ]; then exit 0; fi
		fi

		TESTA_IPS_ANTES_DE_INICIAR
		INICIANDO
		LIMPANDO_REGRAS
		DEFININDO_POLITICAS_PRINCIPAIS
		BLOQUEIO_DE_COMUNICACAO
		ESTADO_DE_CONEXAO
		PROTECAO_CONTRA_ATAQUES
		REDIRECIONA
		GENTE_FINA_INTERNO
		GENTE_FINA_PARA_FW
		OUTROS_BLOQUEIOS
		OUTRAS_LIBERACOES
		LIBERA_PORTA_ENTRADA_FW_ORIGEM_INTERNA
		LIBERA_PORTA_ENTRADA_FW_ORIGEM_GERAL
		PERMISSAO_DE_LOOPBACK
		PING #fazer regra para permitir repasse de pings
		DEFINE_DNS
		BLOQUEIO_DE_SITES
		BLOQUEIO_DE_IPS
		LIBERA_PORTA_REPASSE_ORIGEM_INTERNA
		LIBERA_PORTA_REPASSE_ORIGEM_GERAL
		CONECTIVIDADE_SOCIAL
		DIOPS_ANS
		NAT
		PROXY_TRANSPARENTE
		ULTIMAS_REGRAS
		FINALIZANDO
	;;

	clean)
		LEITURA_DE_VARIAVEIS
		INICIANDO
		LIMPANDO_REGRAS
		LIMPO
		NAT
		REDIRECIONA
		PROXY_TRANSPARENTE
		FINALIZANDO
	;;

	help)
		AJUDA
	;;

	*)
	echo "Uso: $0 {start|stop|clean|ip-test|help} [-d]"
	;;
esac
