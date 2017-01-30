<?php

namespace Picoss\CvssBundle\Validator\Constraints;

use Symfony\Component\Validator\Constraint;

/**
 * @Annotation
 */
class Cvss3 extends Constraint
{
    public $message = 'Cvss3 vector "%vector%" is invalid.';
}