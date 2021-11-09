<?php

namespace YWH\Cvss;

use PHPUnit\Framework\TestCase;
use Symfony\Component\OptionsResolver\Exception\InvalidOptionsException;
use Symfony\Component\OptionsResolver\Exception\UndefinedOptionsException;
use YWH\Cvss\Cvss3;
use Symfony\Component\OptionsResolver\Exception\MissingOptionsException;

class Cvss3Test extends TestCase
{
    public function testParser()
    {
        $vector = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:N';

        $cvss = new Cvss3();
        $cvss->setVector($vector);

        $this->assertSame(10.0, $cvss->getBaseScore());
    }

    public function testNullVector()
    {
        $this->expectException(\TypeError::class);

        $cvss = new Cvss3();
        $cvss->setVector(null);
    }

    public function testWrongVectorHead()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectDeprecationMessage('Cvss vector "foo:3.0/" is not valid. Must start with "CVSS:3.0"');

        $vector = 'foo:3.0/';

        $cvss = new Cvss3();
        $cvss->setVector($vector);
    }

    public function testWrongVectorBaseMetric()
    {
        $this->expectException(UndefinedOptionsException::class);

        $vector = 'CVSS:3.0/foo:bar';

        $cvss = new Cvss3();
        $cvss->setVector($vector);
    }

    public function testMissingBaseMetric()
    {
        $this->expectException(MissingOptionsException::class);

        $vector = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H';

        $cvss = new Cvss3();
        $cvss->setVector($vector);
    }

    public function testWrongBaseMetricValue()
    {
        $this->expectException(InvalidOptionsException::class);

        $vector = 'CVSS:3.0/AV:foo/AC:L/PR:N/UI:N/S:U/C:H/I:H:/A:H';

        $cvss = new Cvss3();
        $cvss->setVector($vector);
    }

    public function testRoundUp()
    {
        $this->assertEquals(Cvss3::roundUp(4.02, 1), 4.1);
        $this->assertEquals(Cvss3::roundUp(4.00, 1), 4.0);
    }

    /**
     * @dataProvider baseVectorProvider
     *
     * @param string     $vector
     * @param float      $baseScore
     * @param null|float $temporalScore
     * @param null|float $environmentalScore
     * @param null|float $baseSeverity
     * @param null|float $temporalSeverity
     * @param null|float $environmentalSeverity
     */
    public function testBaseVector($vector, $baseScore, $temporalScore = null, $environmentalScore = null, $baseSeverity = null, $temporalSeverity = null, $environmentalSeverity = null)
    {
        $cvss = new Cvss3();
        $cvss->setVector($vector);

        $this->assertEquals($cvss->getBaseScore(), $baseScore);
        if (null !== $temporalScore) {
            $this->assertEquals($cvss->getTemporalScore(), $temporalScore);
        }
        if (null !== $environmentalScore) {
            $this->assertEquals($cvss->getEnvironmentalScore(), $environmentalScore);
        }
        if (null !== $baseSeverity) {
            $this->assertEquals($cvss->getBaseScoreSeverity(), $baseSeverity);
        }
        if (null !== $temporalSeverity) {
            $this->assertEquals($cvss->getTemporalScoreSeverity(), $temporalSeverity);
        }
        if (null !== $environmentalSeverity) {
            $this->assertEquals($cvss->getEnvironmentalScoreSeverity(), $environmentalSeverity);
        }
    }

    public function baseVectorProvider()
    {
        return [
            ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0, 0, 0, 'N'],
            ['CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N', 2.7],
            ['CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', 3.1, null, null, 'L'],
            ['CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L', 4.2],
            ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N', 5.8],
            ['CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1, null, null, 'M'],
            ['CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N', 6.4],
            ['CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N', 6.8],
            ['CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 6.8],
            ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5],
            ['CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 7.8, null, null, 'H'],
            ['CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8],
            ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
            ['CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9, null, null, 'C'],
            ['CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N/E:U/RL:T/RC:C', 2.7, 2.4],
            ['CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N/E:U/RL:T/RC:C', 7.6, 6.7],
            ['CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N/RC:R', 7.6, 7.3],
            ['CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N/RC:R/CR:H/MAC:H/MS:U', 7.6, 7.3, 6.2],
            ['CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:H/IR:M/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:U/MC:H/MI:N/MA:L', 9.1, 7.4, 5.4],
            ['CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N/RL:T/RC:C/CR:H/MAC:H/MPR:L/MS:U/MC:N/MI:L/MA:H', 5.5, 5.3, 5.7],
            ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H/RL:T/RC:C/CR:L/IR:M/AR:H/MAV:P/MAC:L/MPR:L/MC:H/MI:H/MA:H', 9.9, 9.6, 7.2],
            ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:F/MC:H/MI:H/MA:H', 7.3, 7.1, 9.6],
            ['CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
            ['CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N', 6.4],
            ['CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', 3.1],
            ['CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9],
            ['CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L', 4.2],
            ['CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8],
            ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/CR:M/MC:N/MI:N/MA:N', 5.3, 5.3, 0],
        ];
    }

    /**
     * @dataProvider severityProvider
     *
     * @param float       $score
     * @param null|string $severity
     */
    public function testSeverity(float $score, ?string $severity)
    {
        $this->assertSame(Cvss3::getSeverity($score), $severity);
    }

    public function severityProvider()
    {
        return [
            [0, 'N'],
            [0.1, 'N'],
            [0.2, 'L'],
            [1, 'L'],
            [3.9, 'L'],
            [4, 'M'],
            [5, 'M'],
            [6.9, 'M'],
            [7, 'H'],
            [8, 'H'],
            [8.9, 'H'],
            [9, 'C'],
            [9.5, 'C'],
            [10, 'C'],
            [11, null],
            [-1, null],
        ];
    }
}