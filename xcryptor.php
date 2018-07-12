<?php
	##########################
	##			##
	##	XcryptOR	##
	##		@MrSRK  ##
	##########################
	
	//$text="Αρνάκι άσπρο και παχύ της μάνας του καμάρι!";
	//$text="Arnaki aspro kai paxi ths panas tou kamari";
	$text=file_get_contents('burning.png');  //Any File :D
	//print "Text: ".$text."\n";
	print "Text Length: ".strlen($text)."\n";
	//$key = bin2hex(openssl_random_pseudo_bytes(16)); //(16)->32 strlen
	$key='{V1z10n}{Gr0Up}{N3W}{L0cK}{C1Ph3r}';
	print "Key Length: ".strlen($key)."\n";
	print "Key. ".$key."\n\n";
	
	/*###########  LOCK  ##############*/
	$cipherText=lock($text,$key);
	//print $cipherText."\n\n";
	print "Cipher Text legth: ".strlen($cipherText)."\n";
	$text=file_put_contents('burning.png.lock',$cipherText);
	
	/*###########  UNLOCK  ##############*/
	$text=unlock($cipherText,$key);
	//print $text."\n";
	
	
	$text=file_put_contents('burning-unlock.png',$text);
	
	//####################################
	function lock($text,$key,$rounds=1)
	{
		$binText=str2bin($text);
		$binKey=str2bin($key);
		$binKeys=str_split($binKey,8);
		foreach($binKeys as $k=>$v)
			$binText=binXor2($binText,$v);
		return compress($binText);
	}
	function unlock($cipherText,$key,$rounds=1)
	{
		$cipherText=uncompress($cipherText);
		$binKey=str2bin($key);
		$binKeys=str_split($binKey,8);
		$binKeys=array_reverse($binKeys);
		foreach($binKeys as $k=>$v)
			$cipherText=xorBin2($cipherText,$v);
		$text=bin2str($cipherText);
		return $text;
	}
	//####################################
	function compress($str)
	{
		$str=str_split($str,8);
		foreach($str as $k=>$v)
			$str[$k]=setbase64($v);
		$str=join($str);
		$str=gzcompress($str);
		return $str;
	}
	function uncompress($str)
	{
		$str=gzuncompress($str);
		$str=str_split($str,2);
		foreach($str as $k=>$v)
			$str[$k]=getbase64($v);
		return join($str);
	}
	//####################################
	function xorBin($textBin,$keyBin)
	{
		$textBin=str_split($textBin);
		$keyBin=str_split($keyBin);
		$cipherBin=array();
		foreach($textBin as $k=>$v)
		{
			$kk=$k-floor($k/count($keyBin))*count($keyBin);
			$cipherBin[]=$v==0?$keyBin[$kk]:($keyBin[$kk]?0:1);
		}
		return join($cipherBin);
	}
	function binXor($textBin,$keyBin)
	{
		$textBin=str_split($textBin);
		$keyBin=str_split($keyBin);
		$cipherBin=array();
		foreach($textBin as $k=>$v)
		{
			$kk=$k-floor($k/count($keyBin))*count($keyBin);
			$cipherBin[]=$v!=$keyBin[$kk]?1:0;
		}
		return join($cipherBin);
	}
	//####################################
	function str2bin($str)
	{
		$hex=unpack("H*",bin2hex($str));
		$hex=str_split($hex[1],2);
		$bin=array();
		foreach($hex as $k=>$v)
			$bin[]=str_pad(base_convert($v,16,2),8,"0",STR_PAD_LEFT);
		return join($bin);
	}
	function bin2str($bin)
	{
		$bin=str_split($bin,8);
		$hex=array();
		foreach($bin as $k=>$v)
			$hex[]=pack("H*",base_convert($v,2,16));
		return hex2bin(join($hex));
	}
	//####################################
	//####           Decode           ####
	//####################################
	function xorBin2($textBin,$keyBin)
	{
		$textBinLen=strlen($textBin)/8;
		$textBin=str_split($textBin);
		$keyBin=str_split($keyBin);
		$cipherBin=array();
		$b=$keyBin[0];
		foreach($textBin as $k=>$v)
		{
			$kk=$k-floor($k/count($keyBin))*count($keyBin);
			$b=$textBin[$k]==0?$b:($b?0:1);
			$textBin[$k]=$b==0?$keyBin[$kk]:($keyBin[$kk]?0:1);
		}
		$k=0;
		for($i=0;$i<$textBinLen;$i++)
			for($j=$i;$j<count($textBin);$j+=$textBinLen)
			{
				$kk=$k-floor($k/count($keyBin))*count($keyBin);
				$cipherBin[]=$textBin[$j];
				$k++;
			}
		return join($cipherBin);
	}
	//####################################
	//####           Encode           ####
	//####################################
	function binXor2($textBin,$keyBin)
	{
		$textBinLen=strlen($textBin)/8;
		$textBin=str_split($textBin);
		$keyBin=str_split($keyBin);
		$cipherBin=array();
		$k=0;
		$b=$keyBin[0];
		for($i=0;$i<8;$i++)
			for($j=$i;$j<count($textBin);$j+=8)
			{
				$kk=$k-floor($k/count($keyBin))*count($keyBin);
				$c=$textBin[$j]!=$keyBin[$kk]?1:0;
				$cb=$c!=$b?1:0;
				$b=$c;
				$k++;
				$cipherBin[]=$cb;
			}
		return join($cipherBin);
	}
	
	function setbase64($bin)
	{
		$map=str_split("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-+");
		$int=base_convert($bin,2,10);
		$r='';
		for($x=64;$x>0;$x--)
			if($int>=$x*64)
			{
				$int-=$x*64;
				$r=$r.$map[$x];
			}
		$r=$r==''?'0':$r;
		$r.=$int<=64&&$int>0?$map[$int]:0;
		return $r;
	}
	function getbase64($b64)
	{
		$map=str_split("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-+");
		$b64=array_reverse(str_split($b64));
		$r=0;
		$p=0;
		foreach($b64 as $k=>$v)
			$r+=array_search($v,$map)*pow(64,$k);
		$r=str_pad(base_convert($r,10,2),8,"0",STR_PAD_LEFT);;
		return $r;
	}
	
	
