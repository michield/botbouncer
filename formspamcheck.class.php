<?php
/*
 * --------------
 * FormSpamCheck class
 * Author: Michiel Dethmers, phpList Ltd, http://www.phplist.com
 * Version 0.1 - 24 August 2011
 * License: LGPL (Lesser Gnu Public License) http://www.gnu.org/licenses/lgpl-3.0.html
 * Free to use, distribute and modify in Open as well as Closed Source software
 * NO WARRANTY WHATSOEVER!
 * ---------------
 * 
 * For more information and how to set up and configure, http://www.phplist.com/formspamclass 
 *
 * This class can be used to stop spammers from cluttering your database with bogus signups
 * posts, comments and whatever else
 *
 * It currently uses three services, stopforumspam.com, project honeypot and akismet
 * If you know of any other services that can be integrated, let me know.
 *
 * Credits: Very loosely based on the original phpBB mod from "microUgly"
 * http://www.phpbb.com/community/viewtopic.php?f=70&t=1349145
 * 
 * 
 */

class FormSpamCheck {

  private $LE = "\n";
  private $honeyPotApiKey = '';
  private $akismetApiKey = '';
  private $akismetBlogURL = 'http://www.phplist.com';
  private $memCached = false;
  private $doHpCheck = false;
  private $akismetEnabled = false;
  private $logRoot = '/var/log/formspam';
  private $logActivity = true;
  private $debug = false;
  private $debugToLog = true;
  private $UA = 'FormSpamCheck class (v.0.0.1)';
  // The StopFormSpam API URL
  private $stopSpamAPIUrl = 'http://www.stopforumspam.com/api';
  public $matchDetails = '';
  public $matchedBy = '';
  public $matchedOn = '';
  private $services = array(
    'SFS' => 'Stop Forum Spam',
    'HP' => 'Honeypot Project',
    'AKI' => 'Akismet'
  );
  
  private $sfsSpamTriggers = array ( ## set a default, in case it's not in config
    'username' => array ( 
      'ban_end' => FALSE, 
      'freq_tolerance' => 2, 
      'ban_reason' => 'You have been identified as a spammer.',
    ),
    'email' => array ( 
      'ban_end' => FALSE, 
      'freq_tolerance' => 0,
      'ban_reason' => 'You have been identified as a spammer.',
    ),
    'ip' => array (  
      'ban_end' => 604800,// 7 days  
      'freq_tolerance' => 1,
      'ban_reason' => 'You have been identified as a spammer.',
    )
  );

  private $akismetFields = array(
      'blog',
      'user_ip',
      'user_agent',
      'referrer',
      'permalink',
      'comment_type',
      'comment_author',
      'comment_author_email',
      'comment_author_url',
      'comment_content'
  );

  function setDebug($setting) {
    $this->debug = (bool)$setting;
  }

  function FormSpamCheck($hpKey = '',$akismetKey = '',$akismetUrl = '') {
    if (!function_exists('curl_init')) {
      print 'curl dependency error';
      return;
    }
    $this->dbg('FSC Init');
    if (!empty($hpKey)) {
      $this->honeyPotApiKey = $hpKey;
#      $this->dbg('HP key set from par');
      $this->doHpCheck = true;
    } elseif (!empty($GLOBALS['honeyPotApiKey'])) {
#      $this->dbg('HP key set from globals');
      $this->honeyPotApiKey = $GLOBALS['honeyPotApiKey'];
      $this->doHpCheck = true;
    }
    if (!empty($akismetKey)) {
#      $this->dbg('akismet key set from par');
      $this->akismetApiKey = $akismetKey;
      $this->akismetEnabled = true;
    } elseif (!empty($GLOBALS['akismetApiKey'])) {
#      $this->dbg('akismet key set from globals');
      $this->akismetApiKey = $GLOBALS['akismetApiKey'];
     # $this->dbg('Set key '.$GLOBALS['akismetApiKey']);
      $this->akismetEnabled = true;
    }
    if (!empty($akismetUrl)) {
#      $this->dbg('akismet url from par '.$akismetUrl);
      $this->akismetBlogURL = $akismetUrl;
    } elseif (!empty($GLOBALS['akismetBlogURL'])) {
#      $this->dbg('akismet url from globals '.$GLOBALS['akismetBlogURL']);
      $this->akismetBlogURL = $GLOBALS['akismetBlogURL'];
      ## @todo verify validity
    } elseif (!empty($_SERVER['HTTP_HOST'])) {
      $this->akismetBlogURL = $_SERVER['HTTP_HOST'];
    }
    
    if (!empty($GLOBALS['logRoot']) && is_writable($GLOBALS['logRoot'])) {
      $this->logRoot = $GLOBALS['logRoot'];
    }
    if (isset($GLOBALS['ForumSpamBanTriggers'])) {
      $this->spamTriggers = $GLOBALS['ForumSpamBanTriggers'];
    }
    if (class_exists('Memcached') && isset($GLOBALS['memCachedServer'])) {
      $this->memCached = new Memcached();
      if (strpos($GLOBALS['memCachedServer'],':') !== FALSE) {
        list($server,$port) = explode(':',$GLOBALS['memCachedServer']);
      } else {
        $server = $GLOBALS['memCachedServer'];
        $port = 11211;
      }
      $this->dbg('memcache: '.$server);
      $this->memCached->addServer($server,$port);
    } else {
      if (!class_exists('Memcached')) {
        $this->dbg('memcache not available, class "Memcached" not found');
      } else {
        $this->dbg('memcache not available, config "memCachedServer" not set');
      }
    }
  }

  private function dbg($msg) {
    if ($this->debugToLog) {
      $this->addLogEntry('fsc-debug.log',$msg);
    }

    if (!$this->debug) return;
    print $msg."\n";
  }

  private function addLogEntry($logFile,$entry) {
    if (empty($this->logRoot)) return;
    if (!$this->logActivity) return;
    $logFile = basename($logFile,'.log');
    if (!is_writable($this->logRoot)) {
      $this->dbg('cannot write logfile '.$this->logRoot.'/'.$logFile.date('Y-m-d').'.log');
      return;
    }
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : ' - ';
    $logEntry = date('Y-m-d H:i:s').' '.$ip.' '.$_SERVER['REQUEST_URI'].' '.$entry;
    file_put_contents($this->logRoot.'/'.$logFile.date('Y-m-d').'.log',$logEntry."\n",FILE_APPEND);
  }

  private function getCache($key) {
    if (!$this->memCached) return false;
    $val = $this->memCached->get($key);
    return $val;
  }

  private function setCache($key,$val,$expiry = 0) {
    if (!$this->memCached) return false;
    if (!$expiry) $expiry = 86400;
    return $this->memCached->set($key,$val,$expiry);
  }

  private function defaults($item) {
    switch ($item) {
      case 'ip': return $_SERVER['REMOTE_ADDR'];
      case 'email': return '';
      case 'username': return 'Anonymous';
      default: return '';
    }
  }

  function honeypotCheck($ip) {
     if (!$this->doHpCheck) return;

    ## honeypot requests will be cached in DNS anyway
    $rev = array_reverse(explode('.', $ip));
    $lookup = $this->honeyPotApiKey.'.'.implode('.', $rev) . '.dnsbl.httpbl.org';

    $rev = gethostbyname($lookup);
    if ($lookup != $rev) {
      $this->matchedOn = 'IP';
      $this->addLogEntry('honeypot.log','SPAM '.$lookup.' '.$rev);
      return true;
    } else {
      $this->addLogEntry('honeypot.log','HAM '.$lookup.' '.$rev);
      return false;
    }
  }

  // Authenticates your Akismet API key
  function akismet_verify_key() {
#    $this->dbg('akismet key check');

    if (empty($this->akismetApiKey)) {
      $this->dbg('No Akismet API Key');
      return false;
    }
    $cached = $this->getCache('akismetKeyValid');
    if (empty($cached)) {
      $request = array(
        'key'=> $this->akismetApiKey,
        'blog' => $this->akismetBlogURL
      );

      $keyValid = $this->doPOST('http://rest.akismet.com/1.1/verify-key',$request);
#      $this->addLogEntry('akismet.log','KEY CHECK: '.$keyValid.' http://rest.akismet.com/1.1/verify-key'.serialize($request));
      $this->setCache('akismetKeyValid',$keyValid);
    } else {
      $this->addLogEntry('akismet.log','KEY CHECK (cached) '.$cache);
      $this->dbg('akismet key (cached) '.$cache);
      $keyValid = $cache;
    }

    if ( 'valid' == $keyValid ) {
      $this->dbg('akismet key valid');
      return true;
    } else {
      $this->dbg('akismet key not valid');
      return false;
    }
  }

  // Passes back true (it's spam) or false (it's ham)
  function akismetCheck($data) {
    if (!$this->akismetEnabled) return false;
    if (!$this->akismet_verify_key()) return false;
    $this->dbg('akismet check');
    if (!is_array($data['ips'])) $data['ips'] = array();

    ## set some values the way akismet expects them
    $data['user_ip'] = !empty($data['ips'][0]) ? $data['ips'][0]: $this->defaults('ip'); ## akismet only handles one IP, so take the first
    $data['comment_author'] = !empty($data['username']) ? $data['username'] : $this->defaults('username');
    $data['comment_author_email'] = !empty($data['email']) ? $data['email'] : $this->defaults('email');
    $data['comment_content'] = !empty($data['content']) ? $data['content'] : $this->defaults('content');
        
    foreach ($this->akismetFields as $field) {
      if (!isset($data[$field])) {
        switch ($field) {
          ## set some defaults that will probably return Ham
          case 'blog': $data['blog'] = $this->akismetBlogURL;break;
          case 'user_ip': $data['user_ip'] = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR']:'';break;
          case 'user_agent': $data['user_agent'] = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT']:'';break;
          case 'referrer': $data['referrer'] = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER']:'http://www.wordpress.com';break;
          case 'permalink': $data['permalink'] = '';break;
          case 'comment_type': $data['comment_type'] = 'comment';break;
          case 'comment_author': $data['comment_author'] = 'Admin';break;
          case 'comment_author_email': $data['comment_author_email'] = 'formspamcheck@gmail.com';break;
          case 'comment_author_url': $data['comment_author_url'] = '';break;
          case 'comment_content': $data['comment_content'] = '';break;
        }
      }
    }

    $cached = $this->getCache('akismet'.md5(serialize($data)));
    if (!empty($cached)) {
      $isSpam = $cached;
      $data['fromcache'] = '(cached)'; // for logging
    } else {
      $isSpam = $this->doPOST('http://'.$this->akismetApiKey.'.rest.akismet.com/1.1/comment-check',$data);
      $this->setCache('akismet'.md5(serialize($data)),$isSpam);
      $data['fromcache'] = '';
    }

    if ( 'true' == $isSpam ) {
      $this->dbg('akismet check SPAM');
      $this->matchedOn = 'unknown';
      $this->addLogEntry('akismet.log',$data['fromcache'].' SPAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
      return true;
    } else {
      $this->dbg('akismet check HAM');
      $this->addLogEntry('akismet.log',$data['fromcache'].' HAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
      return false;
    }
  }

  private function doPOST($url,$requestdata = array()) {
    $date = date('r');
    
    $requestheader = array(
      'Host: '.parse_url($url,PHP_URL_HOST),
      'Content-Type: application/x-www-form-urlencoded',
      'Date: '. $date,
    );
    $data = '';
    foreach ($requestdata as $param => $value) {
      if (!is_array($value)) {
        $data .= $param.'='.urlencode($value).'&';
      } // else -> forget about arrays for now
    }
    $data = substr($data,0,-1);
    $requestheader[] = 'Content-Length: '.strlen($data);
     
    $header = '';
    foreach ($requestheader as $param) {
      $header .= $param.$this->LE;
    }

    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_TIMEOUT, 30);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE); 
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
    curl_setopt($curl, CURLOPT_HTTPHEADER,$requestheader);
    curl_setopt($curl, CURLOPT_DNS_USE_GLOBAL_CACHE, TRUE); 
    curl_setopt($curl, CURLOPT_USERAGENT,$this->UA);
    curl_setopt($curl, CURLOPT_POST, 1);

    curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        
    $result = curl_exec($curl);
    $status = curl_getinfo($curl,CURLINFO_HTTP_CODE);
    if ($status != 200) {
      $error = curl_error($curl);
      $this->dbg('Curl Error '.$status.' '.$error);
    }
    curl_close($curl);
    return $result;
  }

  private function doGET($cUrl) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $cUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    return $result;
  }

  function stopForumSpamCheck($data = array()) {
    if (!sizeof($data['ips'])) {
      $data['ips'][] = $_SERVER['REMOTE_ADDR'];
      if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $data['ips'][] = $_SERVER['HTTP_X_FORWARDED_FOR'];
      }
    }
    
    $isSfsSpam = 0;
    $this->dbg('SFS check');

    $spamTriggers = $this->sfsSpamTriggers;
    if (empty($data['username'])) {
      unset($spamTriggers['username']);
    } else {
      $spamTriggers['username']['value'] = $data['username'];
    }
    if (empty($data['ips'])) {
      unset($spamTriggers['ip']);
    } else {
      $spamTriggers['ip']['value'] = $data['ips'];
    }
    if (empty($data['email'])) {
      unset($spamTriggers['email']);
    } else {
      $spamTriggers['email']['value'] = $data['email'];
    }

    $apiRequest = '';
    foreach ($spamTriggers as $trigger => $banDetails) {
      if (!empty($banDetails['value'])) {
        if (is_array($banDetails['value'])) {
          foreach ($banDetails['value'] as $v) {
            $apiRequest .= $trigger.'[]='.$v.'&';
          }
        } else {
          $apiRequest .= $trigger.'[]='.$banDetails['value'].'&';
        }
      }
    }

    $cached = $this->getCache('SFS'.$apiRequest);
    if (!$cached) {
      $cUrl = $this->stopSpamAPIUrl.'?'.$apiRequest.'&unix';
      $this->addLogEntry('sfs-apicall.log',$cUrl);
      $xml = $this->doGET($cUrl);
          
      if (!$xml) {
        $this->addLogEntry('sfs-apicall.log','FAIL ON XML');
        return false;
      }
      $this->setCache('SFS'.$apiRequest,$xml);
      $cached = ''; // for logging
    } else {
      $xml = $cached;
      $cached = '(cached)'; // for logging
    }
    ## the resulting XML is an 
    $response = simplexml_load_string($xml);
    
  #  var_dump($response);exit;
    $spamMatched = array();
    if ($response->success) {
      $muninEntry = '';
      foreach ($spamTriggers as $trigger => $banDetails) {
        ## iterate over the results found, eg email, ip and username
        foreach ($response->$trigger as $resultEntry) {
          if ($resultEntry->appears) {
         #   var_dump($resultEntry);
            if (
              (
              ## there's a ban end check if it's still in range
              (!empty($banDetails['ban_end']) && $resultEntry->lastseen+$banDetails['ban_end'] > time())
              ## or the ban is permanent
              || empty($banDetails['ban_end'])) &&
              ## check if the frequency is in range
              ((int)$resultEntry->frequency > $banDetails['freq_tolerance'])
            ) {
              $isSfsSpam++;
              $banDetails['matchedon'] = $trigger;
              $this->matchedOn .= $trigger .';';
              $muninEntry .= ' SFSMATCH '.$trigger;
              $banDetails['matchedvalue'] = (string)$resultEntry->value;
              $banDetails['frequency'] = (string)$resultEntry->frequency;
              $spamMatched[] = $banDetails;
            }
          }
        }
      }
      $this->addLogEntry('munin-graph.log',$muninEntry);
    }
    # var_dump($spamMatched);
    $this->matchDetails = $spamMatched;
    if ($isSfsSpam) {
      $this->dbg('SFS check SPAM');
      $this->addLogEntry('sfs.log',$cached.' SPAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
    } else {
      $this->dbg('SFS check HAM');
      $this->addLogEntry('sfs.log',$cached.' HAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
    }
    return $isSfsSpam;
  }

  function isSpam($data,$checkAll = false) {
    $this->dbg('isSpam call');
    ## for external functionality testing, allow "test=ham" or "test=spam"
    if (isset($data['test'])) {
      if ($data['test'] == 'ham') {
        $this->matchedBy = 'HAM test';
        return false;
      } elseif ($data['test'] == 'spam') {
        $this->matchedBy = 'SPAM test';
        return true;
      }
    }
    $isSpam = 0;
    $servicesMatched = array();
    
    ## honeypot will be fastest
    if ($this->doHpCheck && !empty($data['ips'])) {
      $this->dbg('hpCheck');
      foreach ($data['ips'] as $ip) {
        $this->dbg('hpCheck IP '.$ip);
        if ($this->honeypotCheck($ip)) {
          $this->dbg('hpCheck SPAM');
          $this->addLogEntry('munin-graph.log','HPSPAM');
          $this->matchedBy = 'Honeypot Project';
          $servicesMatched[] = 'HP';
          $isSpam++;
        } else {
          $this->addLogEntry('munin-graph.log','HPHAM');
        }
      }
    }
    if ((!$isSpam || $checkAll)) {
      $num = $this->stopForumSpamCheck($data);
      if ($num) {
        $this->matchedBy = 'Stop Forum Spam';
        $this->dbg('SFS SPAM');
        $this->addLogEntry('munin-graph.log','SFSSPAM');
        $isSpam += $num;
        $servicesMatched[] = 'SFS';
      } else {
        $this->addLogEntry('munin-graph.log','SFSHAM');
      }
    }
    if ((!$isSpam || $checkAll) && $this->akismetEnabled) {
      if ($this->akismetCheck($data)) {
        $this->dbg('Akismet SPAM');
        $this->matchedBy = 'Akismet';
        $servicesMatched[] = 'AKI';
        $isSpam++;
        $this->addLogEntry('munin-graph.log','AKISPAM');
      } else {
        $this->addLogEntry('munin-graph.log','AKIHAM');
      }
    }

    ## to test the comparison code below
/*
    $isSpam = 1;
    $servicesMatched = array_keys($this->services);
*/
    
    if ($isSpam) {
      ## Add a log to graph a comparison: a hit on SVC1 -> hit or miss in SVC2?
      foreach (array_keys($this->services) as $svcMain) {
        if (in_array($svcMain,$servicesMatched)) { ## hit on svcMain
          foreach (array_keys($this->services) as $svcCompare) {
            if ($svcCompare != $svcMain) { ## no need to compare with ourselves
              if (in_array($svcCompare,$servicesMatched)) {  ## also a hit on svcCompare
                $this->addLogEntry('munin-graph-compare.log',$svcMain.' - '.$svcCompare.' HIT ');
              } else {
                $this->addLogEntry('munin-graph-compare.log',$svcMain.' - '.$svcCompare.' MISS ');
              }
            }
          }
        }
      }
    }

    $this->dbg('overall SpamScore '.sprintf('%d',$isSpam));
    return $isSpam;
  }

} // eo class

