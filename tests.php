<?php

## some tests on the formspamcheck class

@include 'config.php';
require 'formspamcheck.class.php';

## fetch some obvious spam from eg http://programmermeetdesigner.com/blog/view/techstars_ceo__project_posting_and_the_pmd_difference_/#comments

$spam = array (
  'ips' => array('92.100.15.254','91.121.55.3'),
  'user_agent' => 'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.2.20) Gecko/20110803 Firefox/3.6.20',
  'referrer' => 'http://wordpress.com',
  'username' => 'zusecon',
  'email' => 'l.ihai.y.an.0.01@gmail.com',
  'content' => 'c3cC0T <a href="http://www.postrocknotes.com/acomplia.html">acomplia no script pay master card</a> 445312 <a href="http://www.postrocknotes.com/phentermine.html">overnight phentermine</a> tmioor <a href="http://www.100japanesethings.com/valium.html">valium</a> :) <a href="http://www.100japanesethings.com/xanax.html">but xanax online overnight by fedex</a> 715 <a href="http://www.sincerebro.net/acomplia.html">acomplia</a> =-DD <a href="http://www.haroldlopezgarroz.com/phentermine.html">phentermine</a> %-)))',
);

$ham = array (
  'ips' => array('77.240.14.92'),
  'user_agent' => 'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.2.20) Gecko/20110803 Firefox/3.6.20',
  'referrer' => 'http://wordpress.com',
  'username' => 'HelloWorld',
  'email' => 'phplist@gmail.com',
  'content' => '  First, our friend over at TechStars, David Cohen, responsible for such Web 2.0 companies as J-Squared Media and madKast.com, just let me know he posted a new project over here. Mr. Cohen is a seasoned expert and has lead many rounds of venture funding for his companies. He\'s hoping to find a "RockStar" programmer to put a new project together. Turning to PMD because of its unique userbase of highly qualified, cutting edge, and entrepreneurial motivated users.

Many of you will remember our article about IntenseDebate, the Web 2.0 startup, started by three guys who similarly met on PMD. They, each having different skill sets, came together to contribute to the idea that eventually became IntenseDebate. We\'ve all heard of this story before: A "2.0" company starts, with a small team of motivated programmers, designers and/or writers working in someone\'s basement. What makes this story unique is that the three founding members were located all over the world. Now that they\'ve secured funding (in large part due to TechStars), I\'m sure they\'ve traded in their Skype and AIM for inter-office shouting.

I think this story helps illustrate the difference between PMD and all of the other outsourcing/freelancing/job-boards on the Internet. In addition to having the most highly skilled user base around, ProgrammerMeetDesigner has built a community of people looking to create serious and lasting Internet companies in a cooperative fashion. For the most part, when people meet on PMD, they\'re not looking to scam each other, get one over on the other person, or rip anyone off. At least in my experience/observation I\'ve seen a great deal of synergy created when people come together to work on PMD, and if that\'s not unique in today\'s day and age of outsourcing, I don\'t know what is.',

);

$minimalham = array (
  'ips' => array('77.240.14.92'),
  'username' => 'HelloWorld',
  'email' => 'phplist@gmail.com',
);


$fsc = new FormSpamCheck();
$fsc->setDebug(false);
print "SFS\n";
if ($fsc->stopForumSpamCheck($spam)) {
  print "SPAM\n";
} else {
  print "HAM\n";
}
#var_dump($fsc->matchDetails);

if ($fsc->stopForumSpamCheck($minimalham)) {
  print "SPAM\n";
} else {
  print "HAM\n";
}
#var_dump($fsc->matchDetails);

print 'Akismet'."\n";
if ($fsc->akismetCheck($spam)) {
  print "SPAM\n";
} else {
  print "HAM\n";
}
if ($fsc->akismetCheck($minimalham)) {
  print "SPAM\n";
} else {
  print "HAM\n";
}
print 'Honeypot'."\n";
if ($fsc->honeypotcheck($spam['ips'][0])) {
  print "SPAM\n";
} else {
  print "HAM\n";
}
if ($fsc->honeypotcheck($minimalham['ips'][0])) {
  print "SPAM\n";
} else {
  print "HAM\n";
}
print 'Generic'."\n";
if ($fsc->isSpam($spam)) {
  print "SPAM\n";
  print $fsc->matchedBy."\n";
} else {
  print "HAM\n";
}

if ($fsc->isSpam($minimalham)) {
  print "SPAM\n";
  print $fsc->matchedBy."\n";
} else {
  print "HAM\n";
}


