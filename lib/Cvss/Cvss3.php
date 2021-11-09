<?php

namespace YWH\Cvss;

use InvalidArgumentException;
use Symfony\Component\OptionsResolver\Options;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Class Cvss3
 *
 * @author Romain Honel <r.honel@yeswehack.com>
 * @author Maxime Bouchard <m.bouchard@yeswehack.com>
 */
class Cvss3
{
    /**
     * CVSS Version
     */
    const VERSION = '3.0';

    /**
     * @var string
     */
    static protected string $vectorHead = 'CVSS:3.0';

    /**
     * @var string
     */
    static protected string $metricSeparator = '/';

    /**
     * @var string
     */
    static protected string $valueSeparator = ':';

    /**
     * @var float
     */
    static protected float $exploitabilityCoefficient = 8.22;

    /**
     * @var float
     */
    static protected float $scopeCoefficient = 1.08;

    /**
     * Base metrics definition
     *
     * @var array
     */
    static private array $baseMetrics = [
        'AV' => [
            'N' => 0.85,
            'A' => 0.62,
            'L' => 0.55,
            'P' => 0.2,
        ],
        'AC' => [
            'L' => 0.77,
            'H' => 0.44,
        ],
        'PR' => [
            'N' => 0.85,
            'L' => [
                'unchanged' => 0.62,
                'changed' => 0.68,
            ],
            'H' => [
                'unchanged' => 0.27,
                'changed' => 0.50,
            ],
        ],
        'UI' => [
            'N' => 0.85,
            'R' => 0.62,
        ],
        'S' => [
            'U' => 6.42,
            'C' => 7.52,
        ],
        'C' => [
            'N' => 0,
            'L' => 0.22,
            'H' => 0.56,
        ],
        'I' => [
            'N' => 0,
            'L' => 0.22,
            'H' => 0.56,
        ],
        'A' => [
            'N' => 0,
            'L' => 0.22,
            'H' => 0.56,
        ],
    ];

    /**
     * Temporal metrics definition
     *
     * @var array
     */
    static private array $temporalMetrics = [
        'E' => [
            'X' => 1,
            'U' => 0.91,
            'P' => 0.94,
            'F' => 0.97,
            'H' => 1,
        ],
        'RL' => [
            'X' => 1,
            'O' => 0.95,
            'T' => 0.96,
            'W' => 0.97,
            'U' => 1,
        ],
        'RC' => [
            'X' => 1,
            'U' => 0.92,
            'R' => 0.96,
            'C' => 1,
        ],
    ];

    /**
     * Environment metrics definition
     *
     * @var array
     */
    static private array $environmentalMetrics = [
        'CR' => [
            'X' => 1,
            'L' => 0.5,
            'M' => 1,
            'H' => 1.5,
        ],
        'IR' => [
            'X' => 1,
            'L' => 0.5,
            'M' => 1,
            'H' => 1.5,
        ],
        'AR' => [
            'X' => 1,
            'L' => 0.5,
            'M' => 1,
            'H' => 1.5,
        ],
        'MAV' => [
            'X' => 0,
            'N' => 0.85,
            'A' => 0.62,
            'L' => 0.55,
            'P' => 0.2,
        ],
        'MAC' => [
            'X' => 0,
            'L' => 0.77,
            'H' => 0.44,
        ],
        'MPR' => [
            'X' => 0,
            'N' => 0.85,
            'L' => [
                'unchanged' => 0.62,
                'changed' => 0.68,
            ],
            'H' => [
                'unchanged' => 0.27,
                'changed' => 0.50,
            ],
        ],
        'MUI' => [
            'X' => 0,
            'N' => 0.85,
            'R' => 0.62,
        ],
        'MS' => [
            'X' => 0,
            'U' => 6.42,
            'C' => 7.52,
        ],
        'MC' => [
            'X' => 0,
            'N' => 0,
            'L' => 0.22,
            'H' => 0.56,
        ],
        'MI' => [
            'X' => 0,
            'N' => 0,
            'L' => 0.22,
            'H' => 0.56,
        ],
        'MA' => [
            'X' => 0,
            'N' => 0,
            'L' => 0.22,
            'H' => 0.56,
        ],
    ];

    /**
     * Severity rating scale
     *
     * @var array
     */
    static private array $severityRatingScale = [
        'N' => [
            'min_range' => 0,
            'max_range' => 0.1,
        ],
        'L' => [
            'min_range' => 0.1,
            'max_range' => 3.9,
        ],
        'M' => [
            'min_range' => 4.0,
            'max_range' => 6.9,
        ],
        'H' => [
            'min_range' => 7.0,
            'max_range' => 8.9,
        ],
        'C' => [
            'min_range' => 9.0,
            'max_range' => 10.0,
        ],
    ];

    /**
     * @var array
     */
    private array $vectorInputs = [];

    /**
     * @var array
     */
    private array $vectorLevels = [];

    /**
     * @var float
     */
    private float $baseScore = 0;

    /**
     * @var float
     */
    private float $temporalScore = 0;

    /**
     * @var float
     */
    private float $environmentalScore = 0;

    /**
     * Cvss3 constructor.
     */
    public function __construct()
    {
    }

    /**
     * Parse CVSS vector
     *
     * @param string $vector
     *
     * @throws InvalidArgumentException
     */
    public function setVector(string $vector): void
    {
        if (empty($vector)) {
            throw new InvalidArgumentException(sprintf('Cvss vector "%s" is not valid.', $vector));
        }

        if (!preg_match('/^' . self::$vectorHead . '.*/mi', $vector)) {
            throw new InvalidArgumentException((sprintf('Cvss vector "%s" is not valid. Must start with "%s"', $vector, self::$vectorHead)));
        }

        $this->vectorInputs = self::parseVector($vector);

        $resolver = $this->getInputLevelConfiguration();
        $this->vectorLevels = $resolver->resolve($this->vectorInputs);

        $this->calculate();
    }

    /**
     * Get base CVSS score
     *
     * @return float
     */
    public function getBaseScore(): float
    {
        return $this->baseScore;
    }

    /**
     * Get base score severity
     *
     * @return null|string
     */
    public function getBaseScoreSeverity(): ?string
    {
        return self::getSeverity($this->baseScore);
    }

    /**
     * Get base metric definitions
     *
     * @return array
     */
    public function getBaseMetricDefinitions(): array
    {
        return self::$baseMetrics;
    }

    /**
     * Get temporal score
     *
     * @return float
     */
    public function getTemporalScore(): float
    {
        return $this->temporalScore;
    }

    /**
     * Get temporal score severity
     *
     * @return null|string
     */
    public function getTemporalScoreSeverity(): ?string
    {
        return self::getSeverity($this->temporalScore);
    }

    /**
     * Get temporal metric definitions
     *
     * @return array
     */
    public function getTemporalMetricDefinitions(): array
    {
        return self::$temporalMetrics;
    }

    /**
     * Get environmental score
     *
     * @return float
     */
    public function getEnvironmentalScore(): float
    {
        return $this->environmentalScore;
    }

    /**
     * Get environmental score severity
     *
     * @return null|string
     */
    public function getEnvironmentalScoreSeverity(): ?string
    {
        return self::getSeverity($this->environmentalScore);
    }

    /**
     * Get environmental metric definitions
     *
     * @return array
     */
    public function getEnvironmentalMetricDefinitions(): array
    {
        return self::$environmentalMetrics;
    }

    /**
     * Get severity for the given score
     *
     * @param float $score
     *
     * @return null|string
     */
    static public function getSeverity(float $score): ?string
    {
        foreach (self::$severityRatingScale as $level => $options) {
            if ($score >= $options['min_range'] && $score <= $options['max_range']) {
                return $level;
            }
        }

        return null;
    }

    /**
     * Get overall score
     *
     * @return float
     */
    public function getOverallScore(): float
    {
        if ($this->environmentalScore != $this->baseScore) {
            return $this->environmentalScore;
        } elseif ($this->temporalScore != $this->baseScore) {
            return $this->temporalScore;
        } else {
            return $this->baseScore;
        }
    }

    /**
     * Get overall severity
     *
     * @return null|string
     */
    public function getOverallScoreSeverity(): ?string
    {
        return $this->getSeverity($this->getOverallScore());
    }

    /**
     * Get base vector
     *
     * @return string
     */
    public function getBaseVector(): string
    {
        return self::buildVector(array_intersect_key($this->vectorInputs, self::$baseMetrics));
    }

    /**
     * Get full vector
     *
     * @param bool $omitUndefined Do not include metrics that are not defined (ex:MPR:X)
     *
     * @return string
     */
    public function getVector(bool $omitUndefined = true): string
    {
        $metrics = array();
        foreach ($this->vectorInputs as $name => $value) {
            if ($value != 'X' || !$omitUndefined) {
                $metrics[$name] = $value;
            }
        }

        return self::buildVector($metrics);
    }

    /**
     * Build CVSS vector for the given inputs
     *
     * @param array $inputs
     *
     * @return string
     */
    static function buildVector(array $inputs): string
    {
        $inputs = array_merge(array('CVSS' => self::VERSION), $inputs);

        return implode(self::$metricSeparator, array_map(function ($k, $v) {
            return sprintf('%1$s%3$s%2$s', strtoupper($k), strtoupper($v), self::$valueSeparator);
        }, array_keys($inputs), $inputs));
    }

    /**
     * Parse vector
     *
     * @param string $vector
     *
     * @return array
     */
    static function parseVector(string $vector): array
    {
        $vectorInputs = array();
        $vector = preg_replace('/^' . self::$vectorHead . '[\\' . self::$metricSeparator . ']?/', '', $vector);
        $metrics = explode(self::$metricSeparator, $vector);
        if (count($metrics)) {
            foreach ($metrics as $metric) {
                if (!empty($metric)) {
                    list($name, $value) = explode(self::$valueSeparator, $metric);
                    $vectorInputs[$name] = $value;
                }
            }
        }

        return $vectorInputs;
    }

    /**
     * Use OptionResolver to get input level configuration
     *
     * @return OptionsResolver
     */
    private function getInputLevelConfiguration(): OptionsResolver
    {
        $resolver = new OptionsResolver();
        foreach (self::$baseMetrics as $metric => $values) {
            $resolver
                ->setRequired($metric)
                ->setAllowedValues($metric, array_keys($values));
            if ($metric == 'PR') {
                $resolver->setNormalizer($metric, function (Options $options, $value) use ($metric) {
                    switch ($value) {
                        case 'L':
                        case 'H':
                            if ($this->vectorInputs['S'] == 'U') {
                                $value = (float)self::$baseMetrics[$metric][$value]['unchanged'];
                            } elseif ($this->vectorInputs['S'] == 'C') {
                                $value = (float)self::$baseMetrics[$metric][$value]['changed'];
                            }
                            break;
                        default:
                            $value = (float)self::$baseMetrics[$metric][$value];
                            break;
                    }
                    return $value;
                });
            } else {
                $resolver->setNormalizer($metric, function (Options $options, $value) use ($metric) {
                    return (float)self::$baseMetrics[$metric][$value];
                });
            }
        }

        foreach (self::$temporalMetrics as $metric => $values) {
            $resolver
                ->setDefault($metric, 'X')
                ->setAllowedValues($metric, array_keys($values))
                ->setNormalizer($metric, function (Options $options, $value) use ($metric) {
                    return (float)self::$temporalMetrics[$metric][$value];
                });
        }

        foreach (self::$environmentalMetrics as $metric => $values) {
            $resolver
                ->setDefault($metric, 'X')
                ->setAllowedValues($metric, array_keys($values));
            switch ($metric) {
                case 'MPR':
                    $resolver->setNormalizer($metric, function (Options $options, $value) use ($metric) {
                        $modifiedScope = isset($this->vectorInputs['MS']) && $this->vectorInputs['MS'] != 'X' ? $this->vectorInputs['MS'] : $this->vectorInputs['S'];
                        switch ($value) {
                            case 'X':
                                if ($this->vectorInputs[substr($metric, 1)] == 'N') {
                                    $value = (float)self::$baseMetrics[substr($metric, 1)][$this->vectorInputs[substr($metric, 1)]];
                                } else {
                                    switch ($modifiedScope) {
                                        case 'U':
                                            $value = (float)self::$baseMetrics[substr($metric, 1)][$this->vectorInputs[substr($metric, 1)]]['unchanged'];
                                            break;
                                        case 'C':
                                            $value = (float)self::$baseMetrics[substr($metric, 1)][$this->vectorInputs[substr($metric, 1)]]['changed'];
                                            break;
                                    }
                                }
                                break;
                            case 'L':
                            case 'H':
                                switch ($modifiedScope) {
                                    case 'U':
                                        $value = (float)self::$environmentalMetrics[$metric][$value]['unchanged'];
                                        break;
                                    case 'C':
                                        $value = (float)self::$environmentalMetrics[$metric][$value]['changed'];
                                        break;
                                }
                                break;
                            default:
                                $value = (float)self::$environmentalMetrics[$metric][$value];
                                break;
                        }

                        return $value;
                    });
                    break;
                case 'CR':
                case 'IR':
                case 'AR':
                    $resolver->setNormalizer($metric, function (Options $options, $value) use ($metric) {
                        return (float)self::$environmentalMetrics[$metric][$value];
                    });
                    break;
                default:
                    $resolver->setNormalizer($metric, function (Options $options, $value) use ($metric) {
                        if ($value == 'X') {
                            $value = (float)$options[substr($metric, 1)];
                        } else {
                            $value = (float)self::$environmentalMetrics[$metric][$value];
                        }
                        return $value;
                    });
                    break;
            }
        }

        return $resolver;
    }

    /**
     * Calculate base, temporal and environmental scores
     */
    private function calculate(): void
    {
        /**
         * Base score
         */
        $impactSubScore = 0;
        $impactSubScoreBase = 1 - ((1 - $this->vectorLevels['C']) * (1 - $this->vectorLevels['I']) * (1 - $this->vectorLevels['A']));
        switch ($this->vectorInputs['S']) {
            case 'U':
                $impactSubScore = $this->vectorLevels['S'] * $impactSubScoreBase;
                break;
            case 'C':
                $impactSubScore = $this->vectorLevels['S'] * ($impactSubScoreBase - 0.029) - 3.25 * pow(($impactSubScoreBase - 0.02), 15);
                break;
        }

        $exploitabilitySubScore = self::$exploitabilityCoefficient * $this->vectorLevels['AV'] * $this->vectorLevels['AC'] * $this->vectorLevels['PR'] * $this->vectorLevels['UI'];

        if ($impactSubScore <= 0) {
            $this->baseScore = 0;
        } else {
            switch ($this->vectorInputs['S']) {
                case 'U':
                    $this->baseScore = self::roundUp(min($impactSubScore + $exploitabilitySubScore, 10));
                    break;
                case 'C':
                    $this->baseScore = self::roundUp(min(self::$scopeCoefficient * ($impactSubScore + $exploitabilitySubScore), 10));
                    break;
            }
        }

        /**
         * Temporal score
         */
        $this->temporalScore = self::roundUp($this->baseScore * $this->vectorLevels['E'] * $this->vectorLevels['RL'] * $this->vectorLevels['RC']);

        /**
         * Environmental score
         */
        $modifiedImpactSubScore = 0;
        $modifiedImpactSubScoreBase = min(1 - ((1 - $this->vectorLevels['MC'] * $this->vectorLevels['CR']) * (1 - $this->vectorLevels['MI'] * $this->vectorLevels['IR']) * (1 - $this->vectorLevels['MA'] * $this->vectorLevels['AR'])), 0.915);
        $modifiedScope = isset($this->vectorInputs['MS']) && $this->vectorInputs['MS'] != 'X' ? $this->vectorInputs['MS'] : $this->vectorInputs['S'];
        switch ($modifiedScope) {
            case 'U':
                $modifiedImpactSubScore = $this->vectorLevels['MS'] * $modifiedImpactSubScoreBase;
                break;
            case 'C':
                $modifiedImpactSubScore = $this->vectorLevels['MS'] * ($modifiedImpactSubScoreBase - 0.029) - 3.25 * pow(($modifiedImpactSubScoreBase - 0.02), 15);
                break;
        }

        $modifiedExploitabilitySubScore = self::$exploitabilityCoefficient * $this->vectorLevels['MAV'] * $this->vectorLevels['MAC'] * $this->vectorLevels['MPR'] * $this->vectorLevels['MUI'];

        if ($modifiedImpactSubScore <= 0) {
            $this->environmentalScore = 0;
        } else {
            switch ($modifiedScope) {
                case 'U':
                    $this->environmentalScore = self::roundUp(self::roundUp(min($modifiedImpactSubScore + $modifiedExploitabilitySubScore, 10)) * $this->vectorLevels['E'] * $this->vectorLevels['RL'] * $this->vectorLevels['RC']);
                    break;
                case 'C':
                    $this->environmentalScore = self::roundUp(self::roundUp(min(self::$scopeCoefficient * ($modifiedImpactSubScore + $modifiedExploitabilitySubScore), 10)) * $this->vectorLevels['E'] * $this->vectorLevels['RL'] * $this->vectorLevels['RC']);
                    break;
            }
        }
    }

    /**
     * @param float $number number to round
     *
     * @return float
     */
    public static function roundUp(float $number): float
    {
        return round(ceil($number * 10) / 10, 1);
    }
}