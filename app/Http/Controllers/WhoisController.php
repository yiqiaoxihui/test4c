<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use App\Whois;
class WhoisController extends Controller
{
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
    	$count=Whois::count();
    	echo $count;
        return view('whois', ['input' => '']);
    }
    public function whois_file_json_array(Request $request){
      /***********************test get ip from file*******************************/
      $request_file=base_path()."/left_ip";
      $result_path=base_path()."/result";
      $fpw=fopen($result_path, "w");
      $fp=fopen($request_file, "r");
      $ip_array=array();
      $result_list=array();
      $i=0;
      while(!feof($fp)){
        $ip_array[$i]=fgets($fp);
        $ip_array[$i]=trim($ip_array[$i]);
        $i++;
      }
      fclose($fp);
      /**********************end*test get ip from file****************************/
      #for post ip_str
      #$ip_array=split("\n", $request->ip_list);
      $ip_array=array_filter($ip_array);
      foreach ($ip_array as $ip) {
        $json="";
        $result=array();
        $main_content_array_k_v=array();
        $main_content_array_k_v['ip']=$ip;
        if(preg_match("/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/",$ip))
        {
          $ip_n = bindec(decbin(ip2long($ip)));
          $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->get();
          if(count($rows)<=0){
            $main_content_array_k_v['whois']="";
            $json= json_encode($main_content_array_k_v);
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
          foreach ($rows as $row) 
          {
            if(($row['ip_end']-$row['ip_begin'])<$last_distance)
            {
              //choose the most accurate one
              $last_distance=$row['ip_end']-$row['ip_begin'];
              $result['ip_begin']=$row['ip_begin'];
              $result['ip_end']=$row['ip_end'];
              $result['content']=$row['content'];
            }
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
          $date1="20170901-23:13:00";
          $main_content_array_k_v["whois"]["timestamp"]=$date1;
          array_push($result_list, $main_content_array_k_v);
          #$json= json_encode($main_content_array_k_v,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
        }else{
          $main_content_array_k_v["whois"]="";
          array_push($result_list, $main_content_array_k_v);
          #$json= json_encode($main_content_array_k_v,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
        }
        
        // fwrite($fpw, $json);
        // fwrite($fpw, "\n");
      }
      fclose($fpw);
      $json= json_encode($result_list,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
      return $json;
      print_r("completed!");
    }

    #return whos json list by ip list
    public function pull_ip_list(Request $request)
    {
        $ip_str=$request->ip_list;
        #$ip_str=urldecode($ip_str);
        #return $ip_str;
        #attention:param of shell need use '' tho entry it
        /*$ip_str='103.218.124.14\n211.98.75.226\n154.24.8.30\n210.87.246.88\n222.141.218.230\n120.197.29.6\n58.215.48.180\n144.232.22.172\n203.170.200.142\n220.186.220.113\n202.109.164.31\n138.118.232.1\n201.251.35.193\n147.162.28.21';*/
        $query="python ".base_path()."/get_json_from_db_by_ip_list.py  '".$ip_str."'";
        #return $query;
        $json_list=shell_exec($query);
        return $json_list;
    }
    /**
    *this function query the whois info from db by the url request:whois_api?ip=
    *it just extract the inetnum object and standardizing them
    */
    public function whois_api(Request $request){
      $ip=$request->ip;
      $flag=0;
      $flag=$request->flag;
      #online query
      if ($flag==1)
      {
          $query ="python ".base_path()."/whois_all_complete.py ".$ip." ".base_path()."/whois.config";
          #system print result in the browser straightly
          $json =shell_exec($query);
          #print $raw;
          return $json;
      }
      #query from db
      /********************************************************************/
      /**
      *problem:can not get result
      *solve:the file path in python must be abspath!
      */
      $query ="python ".base_path()."/get_main_object_from_db.py ".$ip." ".base_path()."/whois.config";
      $json = shell_exec($query);
      #print_r($json);
      return $json;
      /********************************************************************/
      /**
      *deal by php,instead by python,above
      */
      $result=array();
      $main_content_array_k_v=array();
      $main_content_array_k_v["IP_addr"]=$ip;
      //input is right ip
      if(preg_match("/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/",$ip))
      {
        $ip_n = bindec(decbin(ip2long($ip)));
        $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->get();
        if(count($rows)<=0)
        {
          query_now($ip);
          $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->get();
          if(count($rows)<=0)
          {
            $main_content_array_k_v["whois"]="";
            return json_encode($result);
          }
        }
        $i=0;
        //init the distance
        $last_distance=$rows[0]['ip_end']-$rows[0]['ip_begin'];
        $result['ip_begin']=$rows[0]['ip_begin'];
        $result['ip_end']=$rows[0]['ip_end'];
        $result['content']=$rows[0]['content'];
        foreach ($rows as $key => $row) 
        {
          if(($row['ip_end']-$row['ip_begin'])<$last_distance)
          {
            //choose the most accurate one
            $last_distance=$row['ip_end']-$row['ip_begin'];
            $result['ip_begin']=$row['ip_begin'];
            $result['ip_end']=$row['ip_end'];
            $result['content']=$row['content'];
          }
        }
        $content=$result['content'];
        $objects_arr=array();
        $main_content="";
        $objects_arr=explode("\n\n",$content);

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
          // if((strpos($item, "NetRange")!==false) || (strpos($item, "inetnum")!==false))
          // {
          //   $main_content=$item;
          // }
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
        //print_r($main_content_array_k_v["whois"]["remarks"]);
        $date1="20170901-23:13:00";
        $main_content_array_k_v["whois"]["timestamp"]=$date1;
        return json_encode($main_content_array_k_v);
      }else{
        $main_content_array_k_v["whois"]="";
        return json_encode($result);
      }
    }
    public function whois_test($ip,$params){
      $result=array();
      if(preg_match("/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/",$ip)){
        $ip_n = bindec(decbin(ip2long($ip)));
        $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->get();
        $i=0;
        foreach($rows as $k=>$row)
        {
          //print_r($row);
          //print_r("</br>");
          $data=$row->content;
          preg_match_all("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/",$data, $ips,PREG_SET_ORDER);
          if(count($ips)>1){
            //print_r(count($ips));
            //print_r($ips[count($ips)-1][1]);
            $ip_begin=bindec(decbin(ip2long($ips[count($ips)-1][1])));
            $ip_end=bindec(decbin(ip2long($ips[count($ips)-1][2])));
            if($ip_n>=$ip_begin && $ip_n<=$ip_end){
              //unset($rows[$k]);
              $result[$i]=$row;
/*              print_r($ips[count($ips)-1][1]);
              echo "~";
              print_r($ips[count($ips)-1][2]);
              print_r("</br>");*/
              $i++;
            }

          }
        }
        //print_r(count($result));
        //return json_encode($result);
        return $result;
      }else{
        return -1;
      }
    }
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
      //echo "</br>--1---";
      //print_r($elements);
      //echo "</br>";
      print_r($ip);
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
        //echo "</br>--2----".(string)$ip_int;
        //print_r($ip_begin);
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
              if(isset($params->sort))
              {
                if ($_POST['search'] == 'ip')
                {
                  $ip=$_POST['content'];
                  $ip_n = bindec(decbin(ip2long($ip)));
                  //echo $ip_n;
                  $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->orderBy($params->sort, $params->order)->get();
                  if(count($rows)>0){
                    $rows=WhoisController::get_detail_one($rows);
                  }
                  $total=count($rows);
                  //$rows=array_slice($result,$params->offset,$params->limit);
                }else{
                  $rows = Whois::where('content', 'like', $_POST['content'])->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
                  $total = Whois::where('content', 'like', '%'.$_POST['content'].'%')->count();
                }
              }
              else{//not isset($params->sort,this is true run.
                if($_POST['search'] == 'ip'){
                  $ip=$_POST['content'];
                  $ip_n = bindec(decbin(ip2long($ip)));
                  $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->get();
                  if(count($rows)>0){
                    $rows=WhoisController::get_detail_one($rows);

                  }
                  $total=count($rows);
/*                  $result=array();
                  $detail_count=0;
                  foreach($rows as $row)
                  {
                    $data=$row->content;
                    preg_match_all("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/",$data, $ips,PREG_SET_ORDER);
                    if(count($ips)>1){
                      $ip_begin=bindec(decbin(ip2long($ips[count($ips)-1][1])));
                      $ip_end=bindec(decbin(ip2long($ips[count($ips)-1][2])));
                      if($ip_n>=$ip_begin && $ip_n<=$ip_end){
                          $result[$detail_count]=$row;
                          $detail_count++;
                      }
                    }
                  }
                  $total=count($result);
                  $rows=array_slice($result,$params->offset,$params->limit);*/
                }else{
                  $rows = Whois::where('content', 'like', '%'.$_POST['content'].'%')->skip($params->offset)->take($params->limit)->get();
                  $total = Whois::where('content', 'like', '%'.$_POST['content'].'%')->count();
                }
              }
              if ($_POST['search'] == 'ip'){
                //$total = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->count();
                if($total<=0){
                  WhoisController::query_now($ip);
                  $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->skip($params->offset)->take($params->limit)->get();
                  $total = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->count();
                }
              }
            }
            else{//all
              if(isset($params->sort)){
                $rows = Whois::skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
              }
              else{
                $rows = Whois::skip($params->offset)->take($params->limit)->get();
              }
              $total = Whois::count(); 
            }
            foreach($rows as $row){
              $row->first = date('Y/m/d H:i:s', $row->first);
              $row->last = date('Y/m/d H:i:s', $row->last);
            }
            $idstart = (int) $params->offset + 1;
            foreach($rows as $row)
            {
              $row->id = $idstart;
              $idstart ++;
            }
            $data = array("rows" => $rows, "total" => $total);
          }
          elseif($_POST['type'] == 'detail'){
            $id = $_POST['id'];
            $msg = Whois::where('_id', $id)->first();
            $msg->first = date('Y/m/d H:i:s', $msg->first);
            $msg->last = date('Y/m/d H:i:s', $msg->last);
            $data = array('message' => $msg);
          }
          return $data;
        }
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
        preg_match("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) {0,1}- {0,1}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/",$data, $ip);
        //print_r(count($ip));
        if(count($ip)>=3){
          $ip_begin=bindec(decbin(ip2long($ip[1])));
          $ip_end=bindec(decbin(ip2long($ip[2])));
          $ip_range_str=$ip[1].$ip[2];
          $hash=md5($ip_range_str);
          //print_r($ip);
          $whois=new Whois;
          $whois->ip_begin=$ip_begin;
          $whois->ip_end=$ip_end;
          $whois->content=$data;
          $whois->hash=$hash;
          $whois->save();
        }else{
          //x.x.x.x/n
          preg_match("/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})/",$data, $ip);
          if(count($ip)>=3){
            //print_r($ip);
            $ip1=ip_n_to_ip($ip[1],$ip[2]);
            $ip_range_str=$ip1[1].$ip1[2];
            $hash=md5($ip_range_str);
            $ip_begin=bindec(decbin(ip2long($ip1[1])));
            $ip_end=bindec(decbin(ip2long($ip1[2])));
            $hash=md5($data);
            $whois=new Whois;
            $whois->ip_begin=$ip_begin;
            $whois->ip_end=$ip_end;
            $whois->content=$data;
            $whois->hash=$hash;
            $whois->save();
            //print_r($ip1);
          }else{
            //x.x.x/n
            preg_match("/inetnum:(\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})/",$data, $ip);
            if(count($ip)>=3){
              //print_r($ip);
              $ip2=ip_n_to_ip($ip[1],$ip[2]);
              $ip_range_str=$ip2[1].$ip2[2];
              $hash=md5($ip_range_str);
              $ip_begin=bindec(decbin(ip2long($ip2[1])));
              $ip_end=bindec(decbin(ip2long($ip2[2])));
              $whois=new Whois;
              $whois->ip_begin=$ip_begin;
              $whois->ip_end=$ip_end;
              $whois->content=$data;
              $whois->hash=$hash;
              $whois->save();
              //print_r($ip2);
            }else{
              //x.x/n
              preg_match("/inetnum:(\d{1,3}\.\d{1,3})\/(\d{1,2})/",$data, $ip);
              if(count($ip)>=3){
                $ip3=ip_n_to_ip($ip[1],$ip[2]);
                $ip_range_str=$ip3[1].$ip3[2];
                $hash=md5($ip_range_str);
                $ip_begin=bindec(decbin(ip2long($ip3[1])));
                $ip_end=bindec(decbin(ip2long($ip3[2])));
                $whois=new Whois;
                $whois->ip_begin=$ip_begin;
                $whois->ip_end=$ip_end;
                $whois->content=$data;
                $whois->hash=$hash;
                $whois->save();
                //print_r($ip3);
              }else{
                //print_r("no respect query data!");
              }
            }
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
          $rows = Whois::where('ip_begin', '<=', $ip_n)->where('ip_end', '>=', $ip_n)->get();
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
/*          foreach ($items as $key => $item) 
          {
            if((strpos($item, "NetRange")!==false) || (strpos($item, "inetnum")!==false))
            {
              $main_content=$item;
            }
          }
          $main_content_array=explode("\n", $main_content);
          $main_content_array_k_v=array();
          $item=array();
          $i=0;
          $useful=array('inetnum','NetRange','descr','CIDR','NetName','Organization','Updated','NetType');
          foreach ($main_content_array as $value) {
            $item=explode(":", $value);
            if(count($item)<2){
              continue;
            }
            if($item[0]=="descr"){
              $main_content_array_k_v[$ip]["whois"]["descr"][$i++]=$item[1];
              //$item[0]="descr".$i++;
            }else{
              $main_content_array_k_v[$ip]["whois"][$item[0]]=$item[1];
            }
          }*/
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
            // if((strpos($item, "NetRange")!==false) || (strpos($item, "inetnum")!==false))
            // {
            //   $main_content=$item;
            // }
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
