<?php

namespace Picoss\CvssBundle\Form\Type;

use Picoss\CvssBundle\Cvss\Cvss3;
use Picoss\CvssBundle\Form\DataTransformer\CvssToArrayTransformer;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class Cvss3Type extends AbstractType
{
    /**
     * @var Cvss3
     */
    private $cvss;

    /**
     * @var string
     */
    private $translationDomain;

    /**
     * Cvss3Type constructor.
     *
     * @param Cvss3 $cvss
     */
    public function __construct(Cvss3 $cvss, $translationDomain = null)
    {
        $this->cvss = $cvss;
        $this->translationDomain = $translationDomain;
    }

    /**
     * {@inheritdoc}
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {

        foreach ($this->cvss->getBaseMetricDefinitions() as $metric => $values) {
            $builder->add($metric, $options['type'], array_merge($this->getDefaultFieldOptions($metric, $values), $options['options'], array(
                'required' => true,
            )));
        }

        if ($options['temporal']) {
            foreach ($this->cvss->getTemporalMetricDefinitions() as $metric => $values) {
                $builder->add($metric, $options['type'], array_merge($this->getDefaultFieldOptions($metric, $values), $options['options']));
            }
        }

        if ($options['environmental']) {
            foreach ($this->cvss->getEnvironmentalMetricDefinitions() as $metric => $values) {
                $builder->add($metric, $options['type'], array_merge($this->getDefaultFieldOptions($metric, $values), $options['options']));
            }
        }

        $builder
            ->addViewTransformer(new CvssToArrayTransformer())
        ;
    }

    /**
     * Get default field configuration
     *
     * @param string $metric
     * @param array $values
     *
     * @return array
     */
    protected function getDefaultFieldOptions($metric, $values)
    {
        return array(
            'choices' => array_combine(array_keys($values), array_keys($values)),
            'choice_label' => function ($value, $key, $index) use ($metric) {
                $this->cvss->getMetricValueTransId($metric, $value);
            },
            'label' => $this->cvss->getMetricTransId($metric),
            'expanded' => true,
            'multiple' => false,
            'translation_domain' => $this->translationDomain ?: 'cvss',
        );
    }

    /**
     * {@inheritdoc}
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefaults(array(
            'type' => ChoiceType::class,
            'options' => array(),
            'temporal' => false,
            'environmental' => false,
        ));

        $resolver->setAllowedTypes('options', 'array');
        $resolver->setAllowedTypes('temporal', 'boolean');
        $resolver->setAllowedTypes('environmental', 'boolean');
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return $this->getBlockPrefix();
    }

    /**
     * {@inheritdoc}
     */
    public function getBlockPrefix()
    {
        return 'picoss_cvss';
    }
}