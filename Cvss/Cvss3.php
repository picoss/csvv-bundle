<?php

namespace Picoss\CvssBundle\Cvss;

use Picoss\Cvss\Cvss3 as BaseCvss3;

class Cvss3 extends BaseCvss3
{

    public function __construct()
    {
        parent::__construct();
    }

    public function getMetricTransId($metric)
    {
        return strtolower(sprintf('cvss.metric.%s', $metric));
    }

    public function getMetricValueTransId($metric, $value)
    {
        return strtolower(sprintf('cvss.metric.%s.%s', $metric, $value));
    }

    public function getBaseSeverityTransId()
    {
        return strtolower(sprintf('cvss.severity.%s', $this->getBaseScoreSeverity()));
    }

    public function getTemporalSeverityTransId()
    {
        return strtolower(sprintf('cvss.severity.%s', $this->getTemporalScoreSeverity()));
    }

    public function getEnvironmentalSeverityTransId()
    {
        return strtolower(sprintf('cvss.severity.%s', $this->getEnvironmentalScoreSeverity()));
    }

}