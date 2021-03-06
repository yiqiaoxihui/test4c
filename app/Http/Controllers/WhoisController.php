<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use App\Whois;
use App\Apnic;
use App\Arin;
use App\Lacnic;
use App\Apnic_mysql;
use App\Arin_mysql;
use App\Apnic_cidr;
use App\Arin_cidr;
use DB;

use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// create a log channel
$log = new Logger('name');
$log->pushHandler(new StreamHandler('your.log', Logger::WARNING));

// add records to the log
$log->warning('Foo');
$log->error('Bar');

class WhoisController extends Controller
{
    public static $ip_server=array(
      [16777216,4278190080,"whois.apnic.net"],
      [33554432,4278190080,"whois.ripe.net"],
      [83886080,4278190080,"whois.ripe.net"],
      [234881024,4278190080,"whois.apnic.net"],
      [411303936,4294705152,"whois.ripe.net"],
      [452984832,4278190080,"whois.apnic.net"],
      [520093696,4278190080,"whois.ripe.net"],
      [603979776,4278190080,"whois.apnic.net"],
      [620756992,4278190080,"whois.ripe.net"],
      [654311424,4278190080,"whois.apnic.net"],
      [687865856,4278190080,"whois.afrinic.net"],
      [704643072,4278190080,"whois.apnic.net"],
      [736100352,4292870144,"whois.apnic.net"],
      [721420288,4278190080,"whois.nic.ad.jp"],
      [771751936,4278190080,"whois.ripe.net"],
      [822083584,4278190080,"whois.apnic.net"],
      [855638016,4278190080,"whois.ripe.net"],
      [989855744,4292870144,"whois.nic.or.kr"],
      [973078528,4261412864,"whois.apnic.net"],
      [1028128768,4294443008,"whois.nic.or.kr"],
      [1028653056,4294705152,"whois.nic.or.kr"],
      [1028915200,4294836224,"whois.nic.or.kr"],
      [1030750208,4293918720,"whois.nic.ad.jp"],
      [1035993088,4293918720,"whois.nic.ad.jp"],
      [1037041664,4294443008,"whois.nic.ad.jp"],
      [1006632960,4261412864,"whois.apnic.net"],
      [1040187392,4278190080,"whois.ripe.net"],
      [1291845632,4278190080,"whois.ripe.net"],
      [1308622848,4261412864,"whois.ripe.net"],
      [1342177280,4026531840,"whois.ripe.net"],
      [1694498816,4278190080,"whois.apnic.net"],
      [1711276032,4278190080,"whois.afrinic.net"],
      [1728053248,4278190080,"whois.apnic.net"],
      [1761607680,4278190080,"whois.afrinic.net"],
      [1778384896,4278190080,"whois.apnic.net"],
      [1828716544,4278190080,"whois.ripe.net"],
      [1845493760,4261412864,"whois.apnic.net"],
      [1889533952,4292870144,"whois.nic.or.kr"],
      [1929379840,4293918720,"whois.nic.or.kr"],
      [1930428416,4294443008,"whois.nic.or.kr"],
      [1981808640,4292870144,"whois.nic.or.kr"],
      [2009071616,4292870144,"whois.nic.or.kr"],
      [1879048192,4160749568,"whois.apnic.net"],
      [2038431744,4290772992,"whois.nic.or.kr"],
      [2105540608,4292870144,"whois.nic.or.kr"],
      [2013265920,4227858432,"whois.apnic.net"],
      [2080374784,4261412864,"whois.apnic.net"],
      [2113929216,4278190080,"whois.apnic.net"],
      [0,2147483648,"whois.arin.net"],
      [2231369728,4278190080,"whois.nic.ad.jp"],
      [2333343744,4294705152,"whois.ripe.net"],
      [2333605888,4294705152,"whois.ripe.net"],
      [2333868032,4294836224,"whois.ripe.net"],
      [2365587456,4290772992,"whois.ripe.net"],
      [2371223552,4294901760,"whois.arin.net"],
      [2369781760,4292870144,"whois.ripe.net"],
      [2371878912,4294705152,"whois.ripe.net"],
      [2372141056,4294901760,"whois.ripe.net"],
      [2432696320,4278190080,"whois.ripe.net"],
      [2452619264,4294901760,"whois.ripe.net"],
      [2513043456,4294836224,"whois.ripe.net"],
      [2513174528,4294901760,"whois.ripe.net"],
      [2513305600,4294836224,"whois.ripe.net"],
      [2513436672,4293918720,"whois.ripe.net"],
      [2514485248,4293918720,"whois.ripe.net"],
      [2515533824,4294443008,"whois.ripe.net"],
      [2516058112,4294705152,"whois.ripe.net"],
      [2528575488,4294901760,"whois.nic.or.kr"],
      [2533228544,4294901760,"whois.ripe.net"],
      [2516582400,4278190080,"whois.apnic.net"],
      [2533359616,4290772992,"whois.ripe.net"],
      [2537553920,4292870144,"whois.ripe.net"],
      [2539651072,4294705152,"whois.ripe.net"],
      [2539913216,4294901760,"whois.ripe.net"],
      [2575302656,4286578688,"whois.nic.ad.jp"],
      [2566914048,4278190080,"whois.apnic.net"],
      [2583691264,4278190080,"whois.afrinic.net"],
      [2615672832,4294443008,"whois.afrinic.net"],
      [2616197120,4294901760,"whois.afrinic.net"],
      [2698510336,4294705152,"whois.ripe.net"],
      [2698772480,4294901760,"whois.ripe.net"],
      [2687238144,4294705152,"whois.ripe.net"],
      [2687500288,4293918720,"whois.ripe.net"],
      [2691891200,4294901760,"whois.afrinic.net"],
      [2691956736,4294705152,"whois.afrinic.net"],
      [2692218880,4294705152,"whois.afrinic.net"],
      [2692481024,4294901760,"whois.afrinic.net"],
      [2744909824,4294705152,"whois.ripe.net"],
      [2745171968,4293918720,"whois.ripe.net"],
      [2747465728,4294901760,"whois.afrinic.net"],
      [2747531264,4294705152,"whois.afrinic.net"],
      [2747793408,4294705152,"whois.afrinic.net"],
      [2734686208,4278190080,"whois.apnic.net"],
      [2751463424,4292870144,"whois.ripe.net"],
      [2753560576,4294443008,"whois.ripe.net"],
      [2754084864,4294901760,"whois.ripe.net"],
      [2759852032,4293918720,"whois.ripe.net"],
      [2761031680,4294836224,"whois.afrinic.net"],
      [2761162752,4294705152,"whois.afrinic.net"],
      [2777612288,4294901760,"whois.afrinic.net"],
      [2777677824,4294705152,"whois.afrinic.net"],
      [2777939968,4294836224,"whois.afrinic.net"],
      [2848980992,4293918720,"whois.apnic.net"],
      [2869952512,4293918720,"whois.ripe.net"],
      [2871001088,4294836224,"whois.ripe.net"],
      [2868903936,4278190080,"whois.apnic.net"],
      [2948595712,4290772992,"whois.nic.or.kr"],
      [2936012800,4278190080,"whois.apnic.net"],
      [2952790016,4278190080,"whois.ripe.net"],
      [2969567232,4278190080,"whois.lacnic.net"],
      [2986344448,4278190080,"whois.ripe.net"],
      [3003121664,4278190080,"whois.lacnic.net"],
      [3019898880,4278190080,"whois.apnic.net"],
      [3036676096,4278190080,"whois.lacnic.net"],
      [3076521984,4292870144,"whois.nic.or.kr"],
      [3053453312,4261412864,"whois.apnic.net"],
      [3103784960,4278190080,"whois.ripe.net"],
      [3120562176,4261412864,"whois.lacnic.net"],
      [3154116608,4278190080,"whois.ripe.net"],
      [3170893824,4278190080,"whois.lacnic.net"],
      [3187671040,4261412864,"whois.lacnic.net"],
      [2147483648,3221225472,"whois.arin.net"],
      [3225878528,4294901760,"whois.ripe.net"],
      [3226008832,4294967040,"whois.arin.net"],
      [3226009088,4294967040,"whois.arin.net"],
      [3225944064,4294901760,"whois.apnic.net"],
      [3228172288,4294901760,"whois.ripe.net"],
      [3228696576,4294836224,"whois.ripe.net"],
      [3228827648,4294836224,"whois.ripe.net"],
      [3228958720,4294901760,"whois.ripe.net"],
      [3231842304,4294901760,"whois.ripe.net"],
      [3231973376,4294705152,"whois.ripe.net"],
      [3221225472,4278190080,"whois.arin.net"],
      [3238002688,4278190080,"whois.ripe.net"],
      [3254779904,4261412864,"whois.ripe.net"],
      [3288334336,4261412864,"whois.afrinic.net"],
      [3321888768,4261412864,"whois.arin.net"],
      [3355443200,4261412864,"whois.lacnic.net"],
      [3389718528,4294901760,"whois.nic.ad.jp"],
      [3389849600,4294901760,"whois.nic.ad.jp"],
      [3389980672,4294901760,"whois.nic.ad.jp"],
      [3390046208,4294705152,"whois.nic.ad.jp"],
      [3390341120,4294934528,"whois.nic.or.kr"],
      [3390504960,4294901760,"whois.nic.ad.jp"],
      [3390570496,4294836224,"whois.nic.ad.jp"],
      [3390701568,4294901760,"whois.nic.ad.jp"],
      [3390963712,4294836224,"whois.nic.or.kr"],
      [3391094784,4294705152,"whois.nic.ad.jp"],
      [3392143360,4294901760,"whois.nic.ad.jp"],
      [3391586304,4294934528,"whois.twnic.net"],
      [3402629120,4293918720,"whois.nic.ad.jp"],
      [3403677696,4292870144,"whois.nic.ad.jp"],
      [3405774848,4290772992,"whois.apnic.net"],
      [3410100224,4294901760,"whois.twnic.net"],
      [3410296832,4294901760,"whois.twnic.net"],
      [3410624512,4294836224,"whois.twnic.net"],
      [3414687744,4294705152,"whois.nic.ad.jp"],
      [3414949888,4294836224,"whois.nic.ad.jp"],
      [3417440256,4294836224,"whois.nic.ad.jp"],
      [3417571328,4294705152,"whois.nic.ad.jp"],
      [3420454912,4292870144,"whois.nic.or.kr"],
      [3388997632,4261412864,"whois.apnic.net"],
      [3422552064,4294705152,"rwhois.gin.ntt.net"],
      [3422552064,4227858432,"whois.arin.net"],
      [3489660928,4261412864,"whois.arin.net"],
      [3512647680,4294959104,"whois.lacnic.net"],
      [3527114752,4294934528,"whois.twnic.net"],
      [3527213056,4294901760,"whois.twnic.net"],
      [3527343104,4294966272,"whois.twnic.net"],
      [3527475200,4294901760,"whois.twnic.net"],
      [3527901184,4294934528,"whois.twnic.net"],
      [3529113600,4294836224,"whois.nic.or.kr"],
      [3529244672,4294705152,"whois.nic.or.kr"],
      [3529506816,4292870144,"whois.nic.or.kr"],
      [3531603968,4292870144,"whois.nic.ad.jp"],
      [3533701120,4293918720,"whois.nic.ad.jp"],
      [3534880768,4294836224,"whois.nic.or.kr"],
      [3535011840,4294705152,"whois.nic.or.kr"],
      [3535536128,4294705152,"whois.nic.ad.jp"],
      [3536060416,4294705152,"whois.nic.ad.jp"],
      [3536584704,4294705152,"whois.nic.or.kr"],
      [3537371136,4294443008,"whois.nic.or.kr"],
      [3537895424,4293918720,"whois.nic.ad.jp"],
      [3538944000,4294901760,"whois.twnic.net"],
      [3539009536,4294950912,"whois.twnic.net"],
      [3539066880,4294959104,"whois.twnic.net"],
      [3539075072,4294836224,"whois.twnic.net"],
      [3539468288,4294443008,"whois.nic.ad.jp"],
      [3539992576,4293918720,"whois.nic.ad.jp"],
      [3541041152,4294705152,"whois.nic.ad.jp"],
      [3541303296,4294836224,"whois.twnic.net"],
      [3541434368,4294901760,"whois.twnic.net"],
      [3542089728,4292870144,"whois.nic.or.kr"],
      [3544907776,4294901760,"whois.twnic.net"],
      [3544711168,4294901760,"whois.twnic.net"],
      [3546808320,4294443008,"whois.nic.or.kr"],
      [3547332608,4294443008,"whois.nic.or.kr"],
      [3547856896,4294443008,"whois.nic.ad.jp"],
      [3548381184,4294443008,"whois.nic.ad.jp"],
      [3551002624,4294443008,"whois.nic.or.kr"],
      [3551526912,4293918720,"whois.nic.or.kr"],
      [3552575488,4290772992,"whois.nic.or.kr"],
      [3523215360,4261412864,"whois.apnic.net"],
      [3583647744,4294959104,"whois.afrinic.net"],
      [3583655936,4294959104,"whois.afrinic.net"],
      [3556769792,4261412864,"whois.ripe.net"],
      [3590324224,4261412864,"whois.arin.net"],
      [3623878656,4278190080,"whois.arin.net"],
      [3640655872,4278190080,"whois.ripe.net"],
      [3659792384,4294705152,"whois.nic.or.kr"],
      [3660054528,4294443008,"whois.nic.ad.jp"],
      [3660578816,4294443008,"whois.nic.or.kr"],
      [3680501760,4292870144,"whois.nic.ad.jp"],
      [3666870272,4293918720,"whois.nic.or.kr"],
      [3667918848,4293918720,"whois.twnic.net"],
      [3671588864,4294443008,"whois.nic.ad.jp"],
      [3672113152,4294443008,"whois.nic.ad.jp"],
      [3672637440,4294443008,"whois.nic.or.kr"],
      [3689938944,4294836224,"whois.nic.or.kr"],
      [3690463232,4294443008,"whois.nic.or.kr"],
      [3657433088,4261412864,"whois.apnic.net"],
      [3695181824,4292870144,"whois.nic.or.kr"],
      [3697278976,4294705152,"whois.nic.ad.jp"],
      [3697737728,4294901760,"whois.nic.or.kr"],
      [3697803264,4294443008,"whois.nic.ad.jp"],
      [3700752384,4294901760,"whois.nic.or.kr"],
      [3716808704,4294836224,"whois.nic.or.kr"],
      [3716939776,4294705152,"whois.nic.or.kr"],
      [3717201920,4293918720,"whois.nic.or.kr"],
      [3718250496,4294443008,"whois.nic.or.kr"],
      [3730833408,4293918720,"whois.nic.or.kr"],
      [3731881984,4294443008,"whois.nic.or.kr"],
      [3732406272,4294836224,"whois.nic.or.kr"],
      [3732537344,4294901760,"whois.nic.or.kr"],
      [3739746304,4294443008,"whois.nic.or.kr"],
      [3690987520,4227858432,"whois.apnic.net"],
    );
#NetRange 后面跟几个空格，按理说0-1个，因为whois爬取的时候处理成1个，但是下载的完整数据并没有处理，导致匹配失败
  public static $useful_object_regs=[
  '/(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9]))) {0,1}- {0,1}((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))/',
  '/(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])/',
  '/(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){2}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])/',
  '/(?:inetnum {0,1}: {0,1}|Network Number {0,}\] {0,1}|NetRange {0,1}: {0,1}|IPv4 Address {0,1}: {0,1})((?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:0{0,3}[1-9][0-9]\.)|(?:0{0,3}[0-9]\.)){1}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:0{0,3}[1-9][0-9])|(?:0{0,3}[0-9])))\/((?:[1-2][0-9])|(?:3[0-2])|[0-9])/'
  ];
  public static $all_key=[
  'NetRange','CIDR','NetName','NetHandle','Parent','NetType','OriginAS','Organization','RegDate','Updated','Comment','Ref',
  'inetnum','aut-num','abuse-c','owner','ownerid','responsible','address',
  'netname','descr','country','geoloc','language','org','sponsoring-org','admin-c',
  'phone','owner-c','tech-c','status','remarks','notify','mnt-by','mnt-lower','mnt-routes','mnt-domains','mnt-irt',
  'inetrev','dns',
  'Network Number','Network Name','Administrative Contact','Technical Contact','Nameserver','Assigned Date','Return Date','Last Update',
  'IPv4 Address','Organization Name','Network Type','Address','Zip Code','Registration Date',
  'created','last-modified','changed','source','parent'
  ];
    //
    public function index(){
    	$count=Apnic::count();
    	#echo $count;
        return view('whois', ['input' => '']);
    }
    /*
    *从whois镜像服务查询ripe,afrinic组织的数据
    */
    public function query_from_local_mysql($ip){
        $command="whois -h 10.10.11.130 -p 8888 ".$ip;
        //$result=shell_exec($command);
        //echo ($command);
        exec($command,$arr);
        //print_r($arr);
        $data="";
        foreach ($arr as $key => $value) {
          if($value==''){
            $data=$data."\n";
          }
          if(substr($value,0,1)=="%" or substr($value,0,1)=="#"){
            continue;
          }
          $data=$data."\n".$value;
        }

        $data=preg_replace("/\n{3,}/","\n\n",$data);
        $data=preg_replace("/ {2,}/"," ",$data);
        $data=trim($data);
        #查询结果可能多个，取最精确的一个
        $position=strpos($data, "Found a referral to");
        if($position>0){
          $position=strpos($data, "inetnum",$position);
          if($position>0)
            $data=substr($data, $position);
        }
        $ip_begin=0;
        $ip_end=0;
        $row=array();
        foreach (WhoisController::$useful_object_regs as $ip_range_reg) {
          preg_match($ip_range_reg,$data, $ip);
          if(count($ip)>=3){
            $ip_begin=bindec(decbin(ip2long($ip[1])));
            $ip_end=bindec(decbin(ip2long($ip[2])));
            $result=array();
            $result['ip_begin']=$ip_begin;
            $result['ip_end']=$ip_end;
            $result['content']=$data;
            $result['time']=date("Y-m-d 00:00:00",time());
            $row=array('0'=>$result);
            return $row;
          }
        }
        return $row;
    }
    /*
    *根据ip，判断该ip属于哪个组织，进而选择从哪个部分查询数据：1.whois镜像服务，2.Mysql数据库，3.mongodb数据库
    */
    public function which_server($ipn){
      $guess_server="";
      foreach (WhoisController::$ip_server as $line) {
        if(($ipn & $line[1])==$line[0]){
          $guess_server=$line[2];
          break;
        }
      }
      return $guess_server;
    }
    /*
    *具体从哪个部分查询数据，注意，mysql部分的数据使用前缀匹配查询
    */
    public function get_data_from_different_database($ip_n,$ip){
      #$ip_n=1194896895;
      #echo $ip_n;
      $guess_server=WhoisController::which_server($ip_n);
      //echo $guess_server;
      $rows=array();
      try {
        switch ($guess_server) {
          case 'whois.apnic.net':
            //echo "apnic";
            
            #$str="select * from apnic where ip_end >=".$ip_n." limit 100";
            //使用前缀匹配查询
            for ($i=32; $i>0; $i--) {
              $ip_predix=$ip_n & (~((1<<(32-$i))-1));
              $rows=DB::connection('mysql')->table('apnic')->select('ip_begin','ip_end','content','time','apnic.id as id')->join('apnic_cidr',function($join)use($ip_predix){
                $join->on('apnic.id','=','apnic_cidr.fid')
                     ->where('apnic_cidr.ip_range_predix','=',$ip_predix);
              })->get();

              $rows=json_decode($rows,true);
              #$rows = Apnic::where('ip_end', '>=', $ip_n)->where('ip_begin', '<=', $ip_n)->limit(10000)->get();
              #$rows =Apnic_cidr::where('ip_range_predix', $ip_predix)->get();
              #$rows=$rows->get_whois;
              if(count($rows)>0){
                foreach ($rows as $row) {
                  #$row['server']="apnic";
                  if($ip_n>=$row['ip_begin'] & $ip_n<=$row['ip_end']){
                    // echo $row['content'];echo "</br>";
                    // echo $ip_n;echo "</br>";
                    // echo $row['ip_end'];echo "</br>";
                    // echo "</br>";
                    break 2;  
                  }
                }
                #echo $rows;
              }
            }

            #$rows =Apnic_mysql::where('ip_end', '>=', $ip_n)->limit(5000)->get();
            #echo $rows;
            #$rows = DB::connection('mysql')->select('select * from apnic where ip_end >=1194896895 limit 100');
            break;
          case 'whois.arin.net':
            //echo "Arin";
            for ($i=32; $i>0; $i--) {
              $ip_predix=$ip_n & (~((1<<(32-$i))-1));
              $rows=DB::connection('mysql')->table('arin')->select('ip_begin','ip_end','content','time','arin.id as id')->join('arin_cidr',function($join)use($ip_predix){
                $join->on('arin.id','=','arin_cidr.fid')
                     ->where('arin_cidr.ip_range_predix','=',$ip_predix);
              })->get();
              //对象转数组
              $rows=json_decode($rows,true);
              #$rows =Apnic_cidr::where('ip_range_predix', $ip_predix)->get();
              #$rows=$rows->get_whois;
              if(count($rows)>0){
                foreach ($rows as $row) {
                  #$row['server']="arin";
                  if($ip_n>=$row['ip_begin'] & $ip_n<=$row['ip_end']){
                    // echo $row['content'];echo "</br>";
                    // echo $ip_n;echo "</br>";
                    // echo $row['ip_end'];echo "</br>";
                    // echo "</br>";
                    break 2;  
                  }
                }
                #echo $rows;
              }
            }
            #$rows =Arin_mysql::where('ip_end', '>=', $ip_n)->limit(5000)->get();
            #$rows =DB::connection('mysql')->select('select * from arin where ip_end >= ? limit 100',[$ip_n]);
            #$rows = Arin::where('ip_end', '>=', $ip_n)->limit(100)->get();
            break;
          case 'whois.ripe.net':
          case 'whois.afrinic.net':
            $rows=WhoisController::query_from_local_mysql($ip);
            break;
          case 'whois.lacnic.net':
            //echo "lacnic";
            $rows = Lacnic::where('ip_end', '>=', $ip_n)->limit(1000)->get();
            break;
          default:
            #其他小RIR，如韩国，日本，都放在lacnic
            #但是也有可能变更的ip，也放到这里面
            $rows = Lacnic::where('ip_end', '>=', $ip_n)->limit(1000)->get();
            # code...
            break;
        }
      } catch (Exception $e) {
        
      }

      //echo $rows;
      return $rows;
    }
      /**
    *this function query the whois info from db by the url request:whois_api?ip=
    *it just extract the inetnum object and standardizing them
    */
    public function whois_api(Request $request){
      $ip=$request->ip;
      //2018/4/17  
      $flag=0;
      $flag=$request->flag;
      $result=array();
      $main_content_array_k_v=array();
      $main_content_array_k_v["IP_addr"]=$ip;
      //input is right ip
      $rows =array();
      if(preg_match("/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/",$ip))
      {
        $ip_n = bindec(decbin(ip2long($ip)));
        switch ($flag) {
          case 0:
            $rows = WhoisController::get_data_from_different_database($ip_n,$ip);
            break;
          case 1:
            #online query
            $rows=WhoisController::query_but_no_update_db($ip);
            break;
          default:
            $rows = WhoisController::get_data_from_different_database($ip_n,$ip);
            break;
        }
        $i=0;
        //init the distance
        if(count($rows)<=0)
        {
          $main_content_array_k_v['whois']="";
          $json= json_encode($main_content_array_k_v);
          return $json;
        }
        $last_distance=4228250625;
        $result['ip_begin']=0;
        $result['ip_end']=4228250625;
        $result['content']="";
        $result['time']="";
        foreach ($rows as $row)
        {

          if(($row['ip_begin']<=$ip_n) && ($row['ip_end']-$row['ip_begin'])<$last_distance)
          {
            //choose the most accurate one
            $last_distance=$row['ip_end']-$row['ip_begin'];
            $result['ip_begin']=$row['ip_begin'];
            $result['ip_end']=$row['ip_end'];
            $result['content']=$row['content'];
            $result['time']=$row['time'];
          }
        }
        $content=$result['content'];
        //echo $content;
        $objects_arr=array();
        $main_content="";
        $objects_arr=explode("\n\n",$content);

        foreach ($objects_arr as $object) 
        {
          foreach (WhoisController::$useful_object_regs as $useful_object_reg) {
            preg_match($useful_object_reg,$object,$matchs);
            //echo count($matchs);
            if (count($matchs)>0) {
              $main_content=$object;
              break 2;
              # code...
            }
          }
        }
        if($main_content=="")
        {
          $main_content_array_k_v['whois']="";
          $json= json_encode($main_content_array_k_v);
          return $json;
        }
        //echo $main_content;
        $main_content_array=explode("\n", $main_content);
        $item=array();
        $i=0;
        $j=0;
        $dns=array();
        $dns_list=['nserver','nsstat','nslastaa'];
        $array_key=['descr','remarks','Comment','mnt-by','mnt-lower','mnt-routes','mnt-domains','changed','dns'];
        $org_list=['org','Organization','Organization Name'];
        //$useful=array('inetnum','NetRange','descr','CIDR','NetName','Organization','Updated','NetType');
        foreach ($main_content_array as $line) {
          foreach (WhoisController::$all_key as $key) {
            # code...
            $position=strpos($line, $key);
            if ($position!==false & $position<=7){
              $key_len=strlen($key);
              $str=trim(substr($line, $position+$key_len));
              if($str[0]!=':' & $str[0]!=']')
                continue;
              $value=trim(substr($str, 1));
              if(in_array($key, $array_key)){
                if(array_key_exists($key, $main_content_array_k_v["whois"])!==true){
                  $main_content_array_k_v["whois"][$key]=array();
                }
                array_push($main_content_array_k_v["whois"][$key],$value);
              }
              elseif (in_array($key, $dns_list)) {
                if(array_key_exists('dns', $main_content_array_k_v["whois"])!==true){
                  $main_content_array_k_v["whois"]['dns']=array();
                }
                $dns[$key]=$value;
                if(count($dns)>=3){
                  array_push($main_content_array_k_v["whois"]['dns'],$dns);
                  $dns=array();
                }
              }
              else{
                $main_content_array_k_v["whois"][$key]=$value;
              }
            }
          }
        }
        $main_content_array_k_v["whois"]["timestamp"]=$result['time'];
        return json_encode($main_content_array_k_v);
      }else{
        $main_content_array_k_v["whois"]="";
        return json_encode($result);
      }
    }
    //从查询到的一组数据中，选择最细的一条数据，即范围最窄的数据。
    public function get_detail_one($rows){
        $last_distance=$rows[0]['ip_end']-$rows[0]['ip_begin'];
        $result=array();
        $result[0]=$rows[0];
        foreach ($rows as $key => $row) {
          if(($row['ip_end']-$row['ip_begin'])<$last_distance)
          {
            //choose the most accurate one
            $last_distance=$row['ip_end']-$row['ip_begin'];
            $result[0]=$row;
          }
        }
        return $result;
    }
    /*
    *接受一串以换行符分隔的ip，进行批量查询，以json格式返回批量查询结果
    */
    public function whois_file_json_array(Request $request){
      $result_list=array();
      $ip_array=explode("\n", $request->ip_list);
      /**********************end*test get ip from request****************************/
      $ip_array=array_filter($ip_array);
      $n=0;
      $fpw=fopen("/var/log/laravel.log", "w");

      foreach ($ip_array as $ip) {
        $json="";
        $result=array();
        $main_content_array_k_v=array();
        $main_content_array_k_v['IP_addr']=$ip;
        //fwrite($fpw, $ip);
        //fwrite($fpw, "\n");
        if(preg_match("/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/",$ip))
        {
            $ip_n = bindec(decbin(ip2long($ip)));
            if($ip_n<=0 || $ip_n>=4294967295){
              $main_content_array_k_v['whois']=array();
              $json= json_encode($main_content_array_k_v);
              array_push($result_list, $main_content_array_k_v);
              //fwrite($fpw, $json);
              //fwrite($fpw, "\n");
              continue;
            }
            $rows =WhoisController::get_data_from_different_database($ip_n,$ip);
            if(count($rows)<=0)
            {
              $main_content_array_k_v['whois']=array();
              //$json= json_encode($main_content_array_k_v);
              array_push($result_list, $main_content_array_k_v);
              fwrite($fpw, "no query:");
              fwrite($fpw, $ip);
              fwrite($fpw, "\n");
              continue;
            }
            //init the distance
            $last_distance=4228250625;
            $result['ip_begin']=0;
            $result['ip_end']=4228250625;
            $result['content']="";
            $result['time']="";
            foreach ($rows as $row)
            {
              if(($row['ip_begin']<=$ip_n) && ($row['ip_end']-$row['ip_begin'])<$last_distance)
              {
                //choose the most accurate one
                $last_distance=$row['ip_end']-$row['ip_begin'];
                $result['ip_begin']=$row['ip_begin'];
                $result['ip_end']=$row['ip_end'];
                $result['content']=$row['content'];
                $result['time']=$row['time'];
              }
            }
            if($result['content']=="")
            {
              $main_content_array_k_v['whois']=array();
              //$json= json_encode($main_content_array_k_v);
              array_push($result_list, $main_content_array_k_v);
              fwrite($fpw, "no in query:");
              fwrite($fpw, $ip);
              fwrite($fpw, "\n");
              $n=$n+1;
              continue;
            }
            $content=$result['content'];
            $object_items=array();
            $main_content="";
            $objects_arr=explode("\n\n",$content);
            foreach ($objects_arr as $object) 
            {
              foreach (WhoisController::$useful_object_regs as $useful_object_reg) 
              {
                preg_match($useful_object_reg,$object,$matchs);
                if (count($matchs)>0) 
                {
                  $main_content=$object;
                  break 2;
                }
              }
            }
            if($main_content=="")
            {
              $main_content_array_k_v['whois']=array();
              //$json= json_encode($main_content_array_k_v);
              array_push($result_list, $main_content_array_k_v);
              fwrite($fpw, "no main content:");
              fwrite($fpw, $ip);
              fwrite($fpw, "\n");
              continue;
            }

            $main_content_array_k_v['whois']=array();
            $main_content_array=explode("\n", $main_content);
            $dns=array();
            $dns_list=['nserver','nsstat','nslastaa'];
            $array_key=['descr','remarks','Comment','mnt-by','mnt-lower','mnt-routes','mnt-domains','changed','dns'];
            $org_list=['org','Organization','Organization Name'];
            //$useful=array('inetnum','NetRange','descr','CIDR','NetName','Organization','Updated','NetType');
            
            foreach ($main_content_array as $line) {
              /*
              *deal this 196.192.16.0 - 196.192.31.255
              *json_encode error:Malformed UTF-8 characters, possibly incorrectly encoded';
              */
              $line=utf8_encode($line);
              if($line ==false){
                //echo "errrrrrrrrrrrrrrrrrrr";
                continue;
              }
              // var_dump($line);
              // echo "</br>";
              foreach (WhoisController::$all_key as $key) {
                $position=strpos($line, $key);
                if ($position!==false & $position<=7){
                  $key_len=strlen($key);
                  $str=trim(substr($line, $position+$key_len));
                  if($str[0]!=':' & $str[0]!=']')
                    continue;
                  $value=trim(substr($str, 1));
                  if(in_array($key, $array_key)){
                    if(array_key_exists($key, $main_content_array_k_v["whois"])!==true){
                      $main_content_array_k_v["whois"][$key]=array();
                    }
                    array_push($main_content_array_k_v["whois"][$key],$value);
                  }
                  elseif (in_array($key, $dns_list)) 
                  {
                    if(array_key_exists('dns', $main_content_array_k_v["whois"])!==true)
                    {
                      $main_content_array_k_v["whois"]['dns']=array();
                    }
                    $dns[$key]=$value;
                    if(count($dns)>=3)
                    {
                      array_push($main_content_array_k_v["whois"]['dns'],$dns);
                      $dns=array();
                    }
                  }
                  else{
                    $main_content_array_k_v["whois"][$key]=$value;
                  }
                }
              }
            }
            $main_content_array_k_v["whois"]["timestamp"]=$result['time'];
            #$main_content_array_k_v["whois"]["number"]=$n;
            array_push($result_list, $main_content_array_k_v);
            //$json= json_encode($result_list,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
            //var_dump($json);
            //fwrite($fpw, $ip);
            //fwrite($fpw, "\n");
            #$json= json_encode($main_content_array_k_v,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
        }else{//error ip
            fwrite($fpw, "error ip:");
            fwrite($fpw, $ip);
            fwrite($fpw, "\n");
            $main_content_array_k_v["whois"]=array();
            array_push($result_list, $main_content_array_k_v);
            #$json= json_encode($main_content_array_k_v,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
          }
      }
      fwrite($fpw, "query end\n");
      //json_last_error()
      $json= json_encode($result_list,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
      if($json==false){
        fwrite($fpw, "json_encode error\n");
        fclose($fpw);
        return json_encode(array());
      }
      fclose($fpw);
      return $json;
      #print_r("completed!");
    }
    /*
    *将12.1/16处理成 12.1.0.0-12.1.255.255
    */
    public function ip_n_to_ip($ip,$ipn){
      $elements=explode(".", $ip);
      $len=count($elements);
      if($len==1){
        $ip=$ip.'.0.0.0';
      }elseif($len==2) {
        $ip=$ip.'.0.0';
      }elseif($len==3) {
        $ip=$ip.'.0';
      }else{

      }
      //print_r($ip);
      if (intval($ipn)<32 & intval($ipn)>0){
        #print ip_num[1]
        $ip_begin="";
        $ip_end="";
        //qu zheng
        $ip_int=floor(intval($ipn)/8);
        $ip_rem=intval($ipn)%8;
        for($i=0;$i<$ip_int;$i++){
          $ip_begin=$ip_begin.$elements[$i].'.';
          $ip_end=$ip_end.$elements[$i].'.';
        }
        $ip_begin=$ip_begin."".(string)(intval($elements[$ip_int]) & (~((1<<(8-$ip_rem))-1)));
        $ip_end=$ip_end."".(string)(intval($elements[$ip_int])|((1<<(8-$ip_rem))-1));
        if ($ip_int<3){
          for($i=$ip_int+1;$i<4;$i++){
            $ip_begin=$ip_begin.'.0';
            $ip_end=$ip_end.'.255';
          }
        }
        //echo "</br>--3----";
        //print_r($ip_begin);
        $result[]=$ip_begin;
        $result[]=$ip_end;
        return $result;
      }
      elseif(intval($ipn)==32){
        $result[]=$ip;
        $result[]=$ip;
        return $result;
      }
      else{
        $result[]='0.0.0.0';
        $result[]='0.0.0.0';
        return $result;
      }
    }
    public function whois_file_json_array1(Request $request){
      $result_list=array();
      $ip_array=explode("\n", $request->ip_list);
      /**********************end*test get ip from request****************************/
      $ip_array=array_filter($ip_array);
      foreach ($ip_array as $ip) {
        $json="";
        $result=array();
        $main_content_array_k_v=array();
        $main_content_array_k_v['IP_addr']=$ip;
        if(preg_match("/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/",$ip))
        {
          $ip_n = bindec(decbin(ip2long($ip)));

          $rows =WhoisController::get_data_from_different_database($ip_n,$ip);
          if(count($rows)<=0)
          {
            $main_content_array_k_v['whois']="";
            $json= json_encode($main_content_array_k_v);
            array_push($result_list, $main_content_array_k_v);
            //fwrite($fpw, $json);
            //fwrite($fpw, "\n");
            continue;
          }
          $i=0;
          array_push($result_list, $main_content_array_k_v);
          #$json= json_encode($main_content_array_k_v,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
        }else{
          $main_content_array_k_v["whois"]="";
          array_push($result_list, $main_content_array_k_v);
          #$json= json_encode($main_content_array_k_v,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
        }
      }
      //fclose($fpw);
      $json= json_encode($result_list,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
      return $json;
      print_r("completed!");
    }
    /*
    *查询界面响应逻辑，包括：
    *1.查询主界面默认显示的多条记录
    *2.按ip查询（search=ip）及按内容查询的逻辑
    */
    public function store()
    {
        $total=0;
        $detail_count=0;
        
        if(isset($_POST['from'])){
          return view('origins', ['input' => $_POST['content']]);
        }
        else{
          if($_POST['type'] == 'data'){
            $params = json_decode($_POST['data']);
            if(strlen($_POST['content']) > 0)
            {
              {//not isset($params->sort,this is true run.
                if($_POST['search'] == 'ip'){
                  $ip=$_POST['content'];
                  $ip_n = bindec(decbin(ip2long($ip)));
                  //return $ip;
                  #echo $ip;
                  $rows =WhoisController::get_data_from_different_database($ip_n,$ip);
                  
                  //$rows = Apnic::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->get();
                  if(count($rows)>0){
                    $rows=WhoisController::get_detail_one($rows);
                  }
                  $total=count($rows);
                  #没有结果，实时查询，入库，再二次查询
                  if($total<=0){
                    $rows = Lacnic::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->skip($params->offset)->take($params->limit)->get();
                    if (count($rows)==0){
                      WhoisController::query_now($ip);
                      $rows = Lacnic::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->skip($params->offset)->take($params->limit)->get();
                      $total = Lacnic::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->count();
                    }
                  }
                }else{
                  #按content内容搜索
                  #权宜之计，仅仅从apnic数据库中按内容查询
                  $rows = Apnic_mysql::where('content', 'like', '%'.$_POST['content'].'%')->skip($params->offset)->take($params->limit)->get();
                  $total = Apnic_mysql::where('content', 'like', '%'.$_POST['content'].'%')->count();
                }
              }
            }
            else{//all，刷新页面是时，分页展示多条数据
              if(isset($params->sort)){
                $rows = Apnic_mysql::skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
              }
              else{
                $rows = Apnic_mysql::skip($params->offset)->take($params->limit)->get();
              }
              $total = Apnic_mysql::count(); 
            }

            $data = array("rows" => $rows, "total" => $total);
          }
          // elseif($_POST['type'] == 'detail'){ #此部分已经无用，之前用于点击列表拉去详细内容，但是上面已经将内容查询过，在前台js中已经更正
          //   $id = $_POST['id'];
          //   $msg = Apnic_mysql::where('id', $id)->first();
          //   #$msg->first = date('Y/m/d H:i:s', $msg->first);
          //   #$msg->last = date('Y/m/d H:i:s', $msg->last);
          //   $data = array('message' => $msg);
          // }
          return $data;
        }
    }#
    public function query_but_no_update_db($ip){
        $command="whois ".$ip;
        //$result=shell_exec($command);
        //echo ($command);
        exec($command,$arr);
        //print_r($arr);
        $data="";
        foreach ($arr as $key => $value) {
          if($value==''){
            $data=$data."\n";
          }
          if(substr($value,0,1)=="%" or substr($value,0,1)=="#"){
            continue;
          }
          $data=$data."\n".$value;
        }

        $data=preg_replace("/\n{3,}/","\n\n",$data);
        $data=preg_replace("/ {2,}/"," ",$data);
        $data=trim($data);
        $position=strpos($data, "Found a referral to");
        if($position>0){
          $position=strpos($data, "inetnum",$position);
          if($position>0)
            $data=substr($data, $position);
        }
        $rows=array();
        #use reg instead of below comment part
        $i=0;
        foreach (WhoisController::$useful_object_regs as $ip_range_reg) {
          $i=$i+1;
          preg_match($ip_range_reg,$data, $ip);
          if(count($ip)>=3){
            if($i>1){
              $ip1=WhoisController::ip_n_to_ip($ip[1],$ip[2]);
              $ip_begin=bindec(decbin(ip2long($ip1[0])));
              $ip_end=bindec(decbin(ip2long($ip1[1])));
            }
            else{
              $ip_begin=bindec(decbin(ip2long($ip[1])));
              $ip_end=bindec(decbin(ip2long($ip[2])));
            }
            #why keep in Lacnic?
            #because Lacnic keep the data besides  ripe,apnic,afrinic,apnic
            #we think if the ip can not get whois data local,it must not be ripe,apnic,afrinic,apnic
            #so we keep the all of the left small rir whois data in Lacnic,which are got by run /home/hitnis/get_whoises/prefect_only_lacnic_V_0_1.py
            #such as whois.nic.or.kr,whois.twnic.net,whois.lacnic.net...
            $result=array();
            $result['ip_begin']=$ip_begin;
            $result['ip_end']=$ip_end;
            $result['content']=$data;
            $result['time']=date("Y-m-d H:i:s",time());
            $rows=array('0'=>$result);
            return  $rows;
          }
        }
        return $rows;
      }
    public function query_now($ip){
        $command="whois ".$ip;
        //$result=shell_exec($command);
        //echo ($command);
        exec($command,$arr);
        //print_r($arr);
        $data="";
        foreach ($arr as $key => $value) {
          if($value==''){
            $data=$data."\n";
          }
          if(substr($value,0,1)=="%" or substr($value,0,1)=="#"){
            continue;
          }
          $data=$data."\n".$value;
        }

        $data=preg_replace("/\n{3,}/","\n\n",$data);
        $data=preg_replace("/ {2,}/"," ",$data);
        $data=trim($data);
        $position=strpos($data, "Found a referral to");
        if($position>0){
          $position=strpos($data, "inetnum",$position);
          if($position>0)
            $data=substr($data, $position);
        }
        #use reg instead of below comment part
        foreach (WhoisController::$useful_object_regs as $ip_range_reg) {
          preg_match($ip_range_reg,$data, $ip);
          if(count($ip)>=3){
            $ip_begin=bindec(decbin(ip2long($ip[1])));
            $ip_end=bindec(decbin(ip2long($ip[2])));
            $hash=md5($ip_begin.$ip_end);
            #why keep in Lacnic?
            #because Lacnic keep the data besides  ripe,apnic,afrinic,apnic
            #we think if the ip can not get whois data local,it must not be ripe,apnic,afrinic,apnic
            #so we keep the all of the left small rir whois data in Lacnic,which are got by run /home/hitnis/get_whoises/prefect_only_lacnic_V_0_1.py
            #such as whois.nic.or.kr,whois.twnic.net,whois.lacnic.net...
            $whois=new Lacnic;
            $whois->ip_begin=$ip_begin;
            $whois->ip_end=$ip_end;
            $whois->content=$data;
            $whois->hash=$hash;
            $whois->time=date("Y-m-d H:i:s",time());
            $whois->save();
          }
        }
    }

    /**
    *this function query the whois info from db by the given ip file,and wirte them into a file
    *it just extract the inetnum object and standardizing them
    */
    public function whois_file_json_line(){
      $fp=fopen("/data/all_ip.txt", "r");
      $fpw=fopen("/data/3689ip_json_3.txt", "w");
      $ip_array=array();   
      $i=0;
      while(!feof($fp)){
        $ip_array[$i]=fgets($fp);
        $ip_array[$i]=trim($ip_array[$i]);
        $i++;
      }
      fclose($fp);
      $ip_array=array_filter($ip_array);
      foreach ($ip_array as $ip) {
        $json="";
        $result=array();
        $result[$ip]["whois"]="";
        if(preg_match("/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/",$ip))
        {
          $ip_n = bindec(decbin(ip2long($ip)));
          $rows = Apnic::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->get();
          if(count($rows)<=0){
            $json= json_encode($result);
            fwrite($fpw, $json);
            fwrite($fpw, "\n");
            continue;
          }
          $i=0;
          //init the distance
          $last_distance=$rows[0]['ip_end']-$rows[0]['ip_begin'];
          $result['ip_begin']=$rows[0]['ip_begin'];
          $result['ip_end']=$rows[0]['ip_end'];
          $result['content']=$rows[0]['content'];
          foreach ($rows as $row) {
            if(($row['ip_end']-$row['ip_begin'])<$last_distance)
            {
              //choose the most accurate one
              $last_distance=$row['ip_end']-$row['ip_begin'];
              $result['ip_begin']=$row['ip_begin'];
              $result['ip_end']=$row['ip_end'];
              $result['content']=$row['content'];
            }
          }
          #this is for get the more accurate info from raw whois data
          #no use because geting more accurate has done in whois_preprocess.py
/*        $second=0;
          $ip_range="";
          foreach($rows as $row)
          {
            $data=$row->content;
            preg_match_all("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/",$data, $ips,PREG_SET_ORDER);
            if(count($ips)>1){
              //print_r(count($ips));
              //print_r($ips[count($ips)-1][1]);
              $ip_begin=bindec(decbin(ip2long($ips[count($ips)-1][1])));
              $ip_end=bindec(decbin(ip2long($ips[count($ips)-1][2])));
              if($ip_n>=$ip_begin && $ip_n<=$ip_end){
                //choose the most accurate one
                if(($ip_end-$ip_begin)<$last_distance){
                  $second=1;
                  $ip_range=$ips[count($ips)-1][0];
                  $last_distance=$ip_end-$ip_begin;
                  $result['ip_begin']=$row['ip_begin'];
                  $result['ip_end']=$row['ip_end'];
                  $result['content']=$row['content'];
                }
              }
            }
          }*/
          $content=$result['content'];
          $objects_arr=array();
          $main_content="";
          $objects_arr=explode("\n\n",$content);
          #this is find main object and some use key-vlaue in main object
          #no use because use reg
          foreach ($objects_arr as $object) 
          {
            foreach (WhoisController::$useful_object_regs as $useful_object_reg) {
              # code...
              preg_match($useful_object_reg,$object,$matchs);
              if (count($matchs)>0) {
                $main_content=$object;
                break 2;
                # code...
              }
            }
          }
          $main_content_array=explode("\n", $main_content);
          $item=array();
          $i=0;
          $j=0;
          $dns=array();
          $dns_list=['nserver','nsstat','nslastaa'];
          $array_key=['descr','remarks','Comment','mnt-by','mnt-lower','mnt-routes','mnt-domains','changed','dns'];
          $org_list=['org','Organization','Organization Name'];
          //$useful=array('inetnum','NetRange','descr','CIDR','NetName','Organization','Updated','NetType');
          foreach ($main_content_array as $line) 
          {
            foreach (WhoisController::$all_key as $key) 
            {
              # code...
              $position=strpos($line, $key);
              if ($position!==false & $position<=7)
              {
                $key_len=strlen($key);
                $str=trim(substr($line, $position+$key_len));
                if($str[0]!=':' & $str[0]!=']')
                  continue;
                $value=trim(substr($str, 1));
                if(in_array($key, $array_key))
                {
                  if(array_key_exists($key, $main_content_array_k_v["whois"])!==true){
                    $main_content_array_k_v["whois"][$key]=array();
                  }
                  array_push($main_content_array_k_v["whois"][$key],$value);
                }
                elseif (in_array($key, $dns_list)) 
                {
                  if(array_key_exists('dns', $main_content_array_k_v["whois"])!==true)
                  {
                    $main_content_array_k_v["whois"]['dns']=array();
                  }
                  $dns[$key]=$value;
                  if(count($dns)>=3)
                  {
                    array_push($main_content_array_k_v["whois"]['dns'],$dns);
                    $dns=array();
                  }
                }
                else{
                  $main_content_array_k_v["whois"][$key]=$value;
                }
                
              }
            }
          }
          $date1="20170901-23:13:00";
          $main_content_array_k_v[$ip]["whois"]["timestamp"]=$date1;
          $json= json_encode($main_content_array_k_v);
        }else{
          $json= json_encode($result);
        }
        fwrite($fpw, $json);
        fwrite($fpw, "\n");
      }
      fclose($fpw);
      print_r("completed!");
    }
}
