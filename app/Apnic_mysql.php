<?php

namespace App;

use Illuminate\Database\Eloquent\Model as Eloquent;

class Apnic_mysql extends Eloquent {

	protected $connection="mysql";
    protected $table = 'apnic';
    public function get_cidrs()
    {
        return $this->hasMany('App\Apnic_cidr','fid','id');
    }
}
