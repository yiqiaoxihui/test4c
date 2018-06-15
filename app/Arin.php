<?php

namespace App;

use Jenssegers\Mongodb\Eloquent\Model as Eloquent;

class Arin extends Eloquent {

	protected $connection="mongodb";
    protected $collection = 'arin';

}
