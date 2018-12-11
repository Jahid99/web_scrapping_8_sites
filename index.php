<?php 

//50.116.24.15
//46.101.125.123

function file_get_contents_curl1($url)
{
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);

    $data = curl_exec($ch);
    curl_close($ch);

    return $data;
}



$html = (string)file_get_contents_curl1('https://api.hackertarget.com/reverseiplookup/?q=46.101.125.123');

$site1 = preg_split('/\s+/', $html);

$site1 = array_filter($site1);



if($site1[0]=='No'){
  $site1 = array();
}


 ?>



<?php 

    function file_get_contents_curl2($url)
{
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);

    $data = curl_exec($ch);
    curl_close($ch);

    return $data;
}



$html = (string)file_get_contents_curl2('https://viewdns.info/reverseip/?host=46.101.125.123&t=1');

$doc = new DOMDocument();
@$doc->loadHTML($html);
$divs = $doc->getElementsByTagName( 'table' )->item(2)->getElementsByTagName( 'td' );

$site2 = array();

$j = 0;


foreach ($divs as $node) {

  $j++;

  if($j>=5 && $j%2==1){

 
    array_push($site2,$node->nodeValue);
    

  }

  

} 

$site2 = $site2;

// echo "<pre>";


// print_r($site2);

// exit;


 ?>




 <?php 

$site3 = array();

 $ch = curl_init();

curl_setopt($ch, CURLOPT_URL, "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=c1e0b40e09b6e2195f251f504345f90712a97304a08a17f3dc37948fb21c27ad&ip=46.101.125.123");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

$result = curl_exec($ch);

$result = json_decode($result);



foreach ($result->resolutions as $thesite) {
   
   array_push($site3,$thesite->hostname);
}


if (curl_errno($ch)) {
    echo 'Error:' . curl_error($ch);
}
curl_close ($ch);


$site3 = $site3;




  ?>



  <?php 




function file_get_contents_curl($url)
{
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);

    $data = curl_exec($ch);
    curl_close($ch);

    return $data;
}



$html = (string)file_get_contents_curl('https://www.rtsak.com/ip-lookup/46.101.125.123');

$doc = new DOMDocument();
@$doc->loadHTML($html);
$divs = $doc->getElementsByTagName( 'div' );

$web_sites = '';

foreach( $divs as $div ){
    if( $div->getAttribute( 'data-clen' ) === '1444' ){

      $cites = $div->getElementsByTagName( 'cite' ); 

      foreach( $cites as $cite ){

        $web_sites.= $cite->nodeValue.' ';

      }

      

    }
  }

 $site4 =  preg_split('/\s+/', $web_sites);

$site4 = array_filter($site4);



   ?>



   <?php 

   function file_get_contents_curl3($url)
{
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.16) Gecko/20110319 Firefox/3.6.16");
    $data = curl_exec($ch);
    curl_close($ch);

    return $data;
}



$html = file_get_contents_curl3('https://ipinfo.io/46.101.125.123');


$doc = new DOMDocument();
@$doc->loadHTML($html);
$divs = $doc->getElementsByTagName( 'ul' )->item(4)->nodeValue;


$site5 = preg_split('/\s+/', $divs);

$site5 = array_filter($site5);






    ?>




    <?php 

    $site6 = array();

        $ch = curl_init();

curl_setopt($ch, CURLOPT_URL,"https://domains.yougetsignal.com/domains.php");
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS,
            "remoteAddress=50.116.24.15&key=&_=");

// In real life you should use something like:
// curl_setopt($ch, CURLOPT_POSTFIELDS, 
//          http_build_query(array('postvar1' => 'value1')));

// Receive server response ...
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$server_output = curl_exec($ch);

$server_outputr = json_decode($server_output);





curl_close ($ch);


$the_sites = $server_outputr->domainArray;


foreach ($the_sites as $the_site) {
    
     array_push($site6,$the_site[0]);
}


$site6 = $site6;




     ?>



<?php 

     $ch = curl_init();

curl_setopt($ch, CURLOPT_URL,"https://www.ipfingerprints.com/scripts/getReverseIP.php");
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS,"remoteHost=46.101.125.123");

// In real life you should use something like:
// curl_setopt($ch, CURLOPT_POSTFIELDS, 
//          http_build_query(array('postvar1' => 'value1')));

// Receive server response ...

curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$server_output = curl_exec($ch);

$server_outputr = json_decode($server_output);

$ip = (strip_tags($server_outputr->reverseIP));

$str = explode("www.",$ip);

curl_close ($ch);

$site7 =   $str;






 ?>



 <?php 


  function file_get_contents_curl_get_link($url)
{
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);

    $data = curl_exec($ch);
    curl_close($ch);

    return $data;
}



$html = file_get_contents_curl_get_link('https://www.robtex.com/premium/?q=46.101.125.123');


//parsing begins here:
$doc = new DOMDocument();
@$doc->loadHTML($html);


  $divs = $doc->getElementsByTagName( 'a' )->item(1)->getAttribute('href');

  



$site8 = array();

 function file_get_contents_curl4($url)
{
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);

    $data = curl_exec($ch);
    curl_close($ch);

    return $data;
}



 $html = file_get_contents_curl4($divs);


$html = preg_split('/\s+/', $html);



for($i=1;$i<count($html)-1;$i++){
    $site = preg_split('/\s+/', $html[$i]);
    $site = explode(",",$site[0]);
    $site = trim($site[0], '"');

     array_push($site8,$site);
    
    
}


$site8 = $site8;


if($site8[0]=='html>'){
  $site8=array();
}



  ?>




<?php 

  $all_sites = array_merge($site1,$site2,$site3,$site4,$site5,$site6,$site7,$site8);

  $all_sites = array_filter($all_sites);




 $all_sites_with_ips = array();

foreach ($all_sites as $all_site) {
    
    $flag = '50.116.24.15;'.$all_site;

    array_push($all_sites_with_ips,$flag);

}



$file = fopen("sitelist.csv","w");

foreach ($all_sites_with_ips as $all_sites_with_ip)
  {
  fputcsv($file,array($all_sites_with_ip));
  }

fclose($file);


 ?>


 <a href="sitelist.csv"> Download The Site List</a>