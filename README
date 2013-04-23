

 * Botbouncer class
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

******** Introduction *********

This class is an attempt to centralise a few anti form spam services on the Internet.

For now, it supports:

* http://www.stopforumspam.com - the Stop Forum Spam service
* http://www.projecthoneypot.org/ - The Honeypot Project
* http://www.akismet.com - The comment spam service from Wordpress


************ Configuration **************

To configure, load the following GLOBALS in your application environment. Generally it's easiest to put
this in the "Config file" of the application:

$GLOBALS['honeyPotApiKey'] = 'abcdefghij'; ## Your Key from the Honeypot Project
$GLOBALS['akismetApiKey']  = 'abcdefghij'; ## Your Key from the Akismet Service
$GLOBALS['akismetBlogURL'] = 'http://yoursite.com'; ## Your website URL
$GLOBALS['logRoot']        = '/tmp';       ## Where to write logfiles

## to avoid overloading the API services, use a memcached service
## calls will be cached for a day
$GLOBALS['memCachedServer'] = 'localhost:11211';

## An array for triggers on spam elements. This is primarily used for the SFS service
## it will default to the one below, you can leave it out if you want

$ForumSpamBanTriggers = array (
  'username' => array (               // ban on username
    'ban_end' => FALSE,               // Permanent ban
    'freq_tolerance' => 2,            // allow when 2 or less in the frequency API field
    'ban_reason' => 'You have been identified as a spammer.',
  ),
  'email' => array (                  // ban on email 
    'ban_end' => FALSE,               // Permanent ban
    'freq_tolerance' => 0,
    'ban_reason' => 'You have been identified as a spammer. ',
  ),
  'ip' => array (                     // ban on ip address 
    'ban_end' => 630000,              // 60*60*24*7 ban for 7 days
    'freq_tolerance' => 1,
    'ban_reason' => 'You have been identified as a spammer.',
  )
);


************** Usage ****************

For now, check the "tests.php" file to see some examples of how to call the class.





