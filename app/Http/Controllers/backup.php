<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use DB;

class LinksController extends Controller
{
    //
    public function index()
    {
        return view('links');
    }

    public function store()
    {
        if($_POST['type'] == 'data'){
          $params = json_decode($_POST['data']);
          if(strlen($_POST['content']) > 0){
            // The content of search is not null.
            if(isset($params->sort)){
              // The result of search should be sorted by $params->sort.
              if ($_POST['search'] == 'as'){
                $rows = DB::table('links')->where('as1', 'like', $_POST['content'])->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
              }
              else{
                $rows = DB::table('links')->where($_POST['search'], 'like', $_POST['content'].'%')->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
              }
            }
            else{
              if ($_POST['search'] == 'as'){
                $rows = DB::table('links')->where('as1', 'like', $_POST['content'])->skip($params->offset)->take($params->limit)->get();
              }
              else{
                $rows = DB::table('links')->where($_POST['search'], 'like', $_POST['content'].'%')->skip($params->offset)->take($params->limit)->get();
              }
            }
            if ($_POST['search'] == 'as'){
              $total = DB::table('links')->where('as1', 'like', $_POST['content'])->count();
            }
            else{
              $total = DB::table('links')->where($_POST['search'], 'like', $_POST['content'].'%')->count();
            }
          }
          else{
            // The content of search is null.
            if(isset($params->sort)){
              $rows = DB::table('links')->skip($params->offset)->take($params->limit)->orderBy($params->sort, $params->order)->get();
            }
            else{
              $rows = DB::table('links')->skip($params->offset)->take($params->limit)->get();
            }
            $total = DB::table('links')->count(); 
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
          $field = $_POST['field'];
          $msg = DB::table('messages')->where('id', $field['message'])->first();
          $msg->first = date('Y/m/d H:i:s', $msg->first);
          $msg->last = date('Y/m/d H:i:s', $msg->last);
          if ($field['as1'][0] ==  '#')
          {
            $row = DB::table('asset')->select('asset as Name')->where('id', substr($field['as1'], 1))->first();
            $as1 = array("result" => $row);
          }
          else
          {
            $row = DB::table('whois_as')->select('asnum as AS', 'asname as Name', 'orgname as Organization', 'country as Country')->where('asnum', $field['as1'])->first();
            if ($row->Organization != ''){
              $row->Name = $row->Name . ', ' . $row->Organization;
            }
            if ($row->Country != ''){
              $row->Name = $row->Name . ', ' . $row->Country;
            }
            unset($row->Organization);
            unset($row->Country);
            if ($row->Name == ""){
              $row->Name = "Unknown";
            }
            $as1 = array("result" => $row);
          }
          if ($field['as2'][0] ==  '#')
          {
            $row = DB::table('asset')->select('asset as Name')->where('id', substr($field['as2'], 1))->first();
            $as2 = array("result" => $row);
          }
          else
          {
            $row = DB::table('whois_as')->select('asnum as AS', 'asname as Name', 'orgname as Organization', 'country as Country')->where('asnum', $field['as2'])->first();
            if ($row->Organization != ''){
              $row->Name = $row->Name . ', ' . $row->Organization;
            }
            if ($row->Country != ''){
              $row->Name = $row->Name . ', ' . $row->Country;
            }
            unset($row->Organization);
            unset($row->Country);
            if ($row->Name == ""){
              $row->Name = "Unknown";
            }
            $as2 = array("result" => $row);
          }
          $data = array('as1' => $as1, 'as2' => $as2, 'message' => $msg);
        }
        return $data;
    }
}
