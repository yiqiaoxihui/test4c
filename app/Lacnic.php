<?php

namespace App;

use Jenssegers\Mongodb\Eloquent\Model as Eloquent;

class Lacnic extends Eloquent {
	
	protected $connection="mongodb";
    protected $collection = 'lacnic';

}
