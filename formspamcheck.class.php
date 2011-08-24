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
 * Credits: Loosely based on the original phpBB mode from "microUgly"
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
  private $hpCheck = false;
  private $akismetEnabled = false;
  private $logRoot = '/var/log';
  private $logActivity = true;
  private $debug = false;
  private $UA = 'FormSpamCheck class (v.0.0.1)';
  // The StopFormSpam API URL
  private $stopSpamAPIUrl = 'http://www.stopforumspam.com/api';
  public $matchDetails = '';
  public $matchedBy = '';
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

  function FormSpamCheck() {
    if (!function_exists('curl_init')) {
      print 'curl dependency error';
      return;
    }
   # $this->dbg('Init');
    if (!empty($GLOBALS['honeyPotApiKey'])) {
      $this->honeyPotApiKey = $GLOBALS['honeyPotApiKey'];
      $this->hpCheck = true;
    }
    if (!empty($GLOBALS['akismetApiKey'])) {
      $this->akismetApiKey = $GLOBALS['akismetApiKey'];
     # $this->dbg('Set key '.$GLOBALS['akismetApiKey']);
      $this->akismetEnabled = true;
    }
    if (!empty($GLOBALS['akismetBlogURL'])) {
      $this->akismetBlogURL = $GLOBALS['akismetBlogURL'];
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
      $this->memCached->addServer($server,$port);
    }
  }

  function dbg($msg) {
    if (!$this->debug) return;
    print $msg."\n";
  }

  function addLogEntry($logFile,$entry) {
    if (empty($this->logRoot)) return;
    if (!$this->logActivity) return;
    $logFile = basename($logFile,'.log');
    if (!is_writable($this->logRoot)) {
      $this->dbg('cannot write logfile '.$this->logRoot.'/'.$logFile.date('Y-m-d').'.log');
      return;
    }
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : ' - ';
    $logEntry = date('Y-m-d H:i:s').' '.$ip.' '.$entry;
    file_put_contents($this->logRoot.'/'.$logFile.date('Y-m-d').'.log',$logEntry."\n",FILE_APPEND);
  }

  function getCache($key) {
    if (!$this->memCached) return false;
    $val = $this->memCached->get($key);
 #   print "Cache for $key:  $val\n";
    return $val;
  }

  function setCache($key,$val,$expiry = 0) {
    if (!$this->memCached) return false;
#    print "Set cache $key = $val\n";
    if (!$expiry) $expiry = 86400;
    return $this->memCached->set($key,$val,$expiry);
  }

  function defaults($item) {
    switch ($item) {
      case 'ip': return $_SERVER['REMOTE_ADDR'];
      case 'email': return '';
      case 'username': return 'Anonymous';
      default: return '';
    }
  }

  function honeypotCheck($ip) {
     if (!$this->hpCheck) return;

    ## honeypot requests will be cached in DNS anyway
    $rev = array_reverse(explode('.', $ip));
    $lookup = $GLOBALS['honeyPotApiKey'].'.'.implode('.', $rev) . '.dnsbl.httpbl.org';

    $rev = gethostbyname($lookup);
    if ($lookup != $rev) {
      $this->addLogEntry('honeypot.log','SPAM '.$lookup.' '.$rev);
      return true;
    } else {
      $this->addLogEntry('honeypot.log','HAM '.$lookup.' '.$rev);
      return false;
    }
  }

  // Authenticates your Akismet API key
  function akismet_verify_key() {
    if (empty($this->akismetApiKey)) {
      $this->dbg('No Akismet API Key');
      return false;
    }
    $cached = $this->getCache('akismetKeyValid');
    if (!empty($cached)) return $cached;
    
    $request = array(
      'key'=> $this->akismetApiKey,
      'blog' => $this->akismetBlogURL
    );

    $keyValid = $this->doPOST('http://rest.akismet.com/1.1/verify-key',$request);

    if ( 'valid' == $keyValid ) {
      $this->setCache('akismetKeyValid',true);
      return true;
    } else {
      $this->setCache('akismetKeyValid',false);
      return false;
    }
  }

  // Passes back true (it's spam) or false (it's ham)
  function akismetCheck($data) {
    if (!$this->akismetEnabled) return false;
    if (!$this->akismet_verify_key()) return false;

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
      $this->addLogEntry('akismet.log',$data['fromcache'].' SPAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
      return true;
    } else {
      $this->addLogEntry('akismet.log',$data['fromcache'].' HAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
      return false;
    }
  }

  function doPOST($url,$requestdata = array()) {
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

  function doGET($cUrl) {
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
    
    $isSfsSpam = false;

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
      foreach ($spamTriggers as $trigger => $banDetails) {
        ## iterate over the results found, eg email, ip and username
        foreach ($response->$trigger as $resultEntry) {
          if ($resultEntry->appears) {
         #   var_dump($resultEntry);
            if (!empty($banDetails['ban_end']) && $resultEntry->lastseen+$banDetails['ban_end'] > time()) {
              $isSfsSpam = true;
              $banDetails['matchedon'] = $trigger;
              $banDetails['matchedvalue'] = (string)$resultEntry->value;
              $banDetails['frequency'] = (string)$resultEntry->frequency;
            }
            if ((int)$resultEntry->frequency > $banDetails['freq_tolerance']) {
              $isSfsSpam = true;
              $banDetails['matchedon'] = $trigger;
              $banDetails['matchedvalue'] = (string)$resultEntry->value;
              $banDetails['frequency'] = (string)$resultEntry->frequency;
            }
          }
          $spamMatched[] = $banDetails;
        }
      }
    }
    # var_dump($spamMatched);
    $this->matchDetails = $spamMatched;
    if ($isSfsSpam) {
      $this->addLogEntry('sfs.log',$cached.' SPAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
    } else {
      $this->addLogEntry('sfs.log',$cached.' HAM '.$data['username'].' '.$data['email'].' '.join(',',$data['ips']));
    }
    return $isSfsSpam;
  }

  function isSpam($data) {
    ## honeypot will be fastest
    if ($this->hpCheck && !empty($data['ips'])) {
      foreach ($data['ips'] as $ip) {
        if ($this->honeypotCheck($ip)) {
          $this->matchedBy = 'Honeypot Project';
          return true;
        }
      }
    }
    if ($this->stopForumSpamCheck($data)) {
      $this->matchedBy = 'Stop Forum Spam';
      return true;
    }
    if ($this->akismetEnabled && $this->akismetCheck($data)) {
      $this->matchedBy = 'Akismet';
      return true;
    }
    return false;
  }

} // eo class

