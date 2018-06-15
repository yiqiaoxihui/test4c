<?php

namespace App;

use Illuminate\Database\Eloquent\Model as Eloquent;

class Apnic_cidr extends Eloquent {

	protected $connection="mysql";
    protected $table = 'apnic_cidr';
    public function get_whois()
    {
    	return $this->belongsTo('App\Apnic_mysql','fid');
    }
}
