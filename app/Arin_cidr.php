<?php

namespace App;

use Illuminate\Database\Eloquent\Model as Eloquent;

class Arin_cidr extends Eloquent {

	protected $connection="mysql";
    protected $table = 'arin_cidr';
}
