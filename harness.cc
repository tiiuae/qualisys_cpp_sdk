#include "Markup.h"
#include "RTProtocol.h"
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider fdp(Data, Size);

  // Create instance of the protocol
  CRTProtocol protocol;

  auto generatePoint = [&fdp]() {
    CRTProtocol::SPoint point;
    point.fX = fdp.ConsumeFloatingPoint<float>();
    point.fY = fdp.ConsumeFloatingPoint<float>();
    point.fZ = fdp.ConsumeFloatingPoint<float>();
    return point;
  };

  auto generateString = [&fdp]() { return fdp.ConsumeRandomLengthString(); };

  auto generateDOF = [&fdp]() {
    return static_cast<CRTProtocol::EDegreeOfFreedom>(
        fdp.ConsumeIntegralInRange<int>(0, 5));
  };

  auto generateDouble = [&fdp]() -> double {
    if (fdp.ConsumeBool()) {
      return std::numeric_limits<double>::quiet_NaN();
    }
    return fdp.ConsumeFloatingPoint<double>();
  };

  auto generateSpecialFloat = [&fdp]() -> float {
    switch (fdp.ConsumeIntegralInRange<int>(0, 4)) {
    case 0:
      return std::numeric_limits<float>::infinity();
    case 1:
      return -std::numeric_limits<float>::infinity();
    case 2:
      return std::numeric_limits<float>::quiet_NaN();
    case 3:
      return std::numeric_limits<float>::denorm_min();
    default:
      return fdp.ConsumeFloatingPoint<float>();
    }
  };

  auto generateBoundedFloat = [&fdp](float min, float max) {
    return min + (fdp.ConsumeFloatingPoint<float>() * (max - min));
  };

  switch (fdp.ConsumeIntegralInRange(0, 22)) {
  case 0: {
    int nmaj = fdp.ConsumeIntegral<int>();
    int nmin = fdp.ConsumeIntegral<int>();
    protocol.SetVersion(nmaj, nmin);
    break;
  }
  case 1: {
    std::string license = fdp.ConsumeRandomLengthString();
    protocol.CheckLicense(license.c_str());
    break;
  }
  case 2: {
    std::string license = fdp.ConsumeRandomLengthString();
    // Buffer overflow here:  ./crash-bc7f8ff5ff6296eca870345dbecbfac4f6d61648
    protocol.LoadProject(license.c_str());
    break;
  }
  case 3: {
    std::string license = fdp.ConsumeRandomLengthString();
    int nsize = fdp.ConsumeIntegral<int>();
    std::string license2 = fdp.ConsumeRandomLengthString(nsize);
    bool overwrite = fdp.ConsumeBool();

    // Buffer overflow here:  ./crash-12f54f76dc1ee7a8811d7ff6d6b3df8ed7279910
    protocol.SaveCapture(license.c_str(), overwrite, (char *)license2.c_str(),
                         nsize);
    break;
  }
  case 4: {
    std::string license = fdp.ConsumeRandomLengthString();
    protocol.LoadCapture(license.c_str());
    break;
  }
  case 5: {
    std::string license = fdp.ConsumeRandomLengthString();

    // Buffer overflow here:  ./crash-630d1e22ceaaad8be0524bbb8072a23a464ae4e6``
    protocol.GetCurrentFrame(license.c_str());
    break;
  }
  case 6: {
    int ncomp = fdp.ConsumeIntegral<int>();
    CRTProtocol::SComponentOptions scompo;
    scompo.mSkeletonGlobalData = fdp.ConsumeBool();
    std::string analch = fdp.ConsumeRandomLengthString();
    scompo.mAnalogChannels = ((char *)analch.c_str());
    // Buffer overflow here:  ./crash-1c6423f82d006a8a3d0423d11780818f385e3fd9
    protocol.GetCurrentFrame(ncomp, scompo);
    break;
  }
  case 7: {
    std::string comps = fdp.ConsumeRandomLengthString();
    protocol.ConvertComponentString(comps.c_str());
    break;
  }
  case 8: {
    unsigned int n = fdp.ConsumeIntegral<unsigned int>();
    std::string prate = fdp.ConsumeRandomLengthString();
    CRTProtocol::EStreamRate esr =
        static_cast<CRTProtocol::EStreamRate>(fdp.ConsumeIntegral<int>() % 4);
    protocol.ConvertRateString(prate.c_str(), esr, n);
    break;
  }
  case 9: {
    unsigned int captureFrequency = fdp.ConsumeIntegral<unsigned int>();
    float captureTime = fdp.ConsumeFloatingPoint<float>();

    bool startOnExtTrig = fdp.ConsumeBool();
    bool startOnTrigNO = fdp.ConsumeBool();
    bool startOnTrigNC = fdp.ConsumeBool();
    bool startOnTrigSoftware = fdp.ConsumeBool();

    CRTProtocol::EProcessingActions processingActions =
        static_cast<CRTProtocol::EProcessingActions>(
            fdp.ConsumeIntegral<unsigned int>() & 0x3FFF);

    CRTProtocol::EProcessingActions rtProcessingActions =
        static_cast<CRTProtocol::EProcessingActions>(
            fdp.ConsumeIntegral<unsigned int>() & 0x3FFF);

    CRTProtocol::EProcessingActions reprocessingActions =
        static_cast<CRTProtocol::EProcessingActions>(
            fdp.ConsumeIntegral<unsigned int>() & 0x3FFF);

    protocol.SetGeneralSettings(&captureFrequency, &captureTime,
                                &startOnExtTrig, &startOnTrigNO, &startOnTrigNC,
                                &startOnTrigSoftware, &processingActions,
                                &rtProcessingActions, &reprocessingActions);

    break;
  }

  case 10: {
    std::vector<CRTProtocol::SSettingsSkeletonHierarchical> skeletons;
    size_t numSkeletons = fdp.ConsumeIntegralInRange<size_t>(0, 5);

    for (size_t i = 0; i < numSkeletons; i++) {
      CRTProtocol::SSettingsSkeletonHierarchical skeleton;
      skeleton.name = generateString();
      skeleton.scale = fdp.ConsumeFloatingPoint<double>();
      skeletons.push_back(skeleton);
    }

    // Heap buffer overflow: ./crash-0ba208730383d4e0e36c5d566518445d2e61f25a
    protocol.SetSkeletonSettings(skeletons);
    break;
  }

  case 11: {
    std::vector<CRTProtocol::SSettings6DOFBody> bodies;
    size_t numBodies = fdp.ConsumeIntegralInRange<size_t>(0, 5);

    for (size_t i = 0; i < numBodies; i++) {
      CRTProtocol::SSettings6DOFBody body;
      body.name = generateString();
      body.color = fdp.ConsumeIntegral<uint32_t>();
      body.filterPreset = generateString();
      body.maxResidual = fdp.ConsumeFloatingPoint<float>();
      body.minMarkersInBody = fdp.ConsumeIntegral<uint32_t>();
      body.boneLengthTolerance = fdp.ConsumeFloatingPoint<float>();

      body.mesh.name = generateString();
      body.mesh.position = generatePoint();
      body.mesh.rotation = generatePoint();
      body.mesh.scale = fdp.ConsumeFloatingPoint<float>();
      body.mesh.opacity = fdp.ConsumeFloatingPoint<float>();

      size_t numPoints = fdp.ConsumeIntegralInRange<size_t>(0, 10);
      for (size_t j = 0; j < numPoints; j++) {
        CRTProtocol::SBodyPoint point;
        point.name = generateString();
        point.fX = fdp.ConsumeFloatingPoint<float>();
        point.fY = fdp.ConsumeFloatingPoint<float>();
        point.fZ = fdp.ConsumeFloatingPoint<float>();
        point.virtual_ = fdp.ConsumeBool();
        point.physicalId = fdp.ConsumeIntegral<uint32_t>();
        body.points.push_back(point);
      }

      bodies.push_back(body);
    }

    protocol.Set6DOFBodySettings(bodies);
    break;
  }

  case 12: {
    unsigned int plateID = fdp.ConsumeIntegral<unsigned int>();
    CRTProtocol::SPoint corner1 = generatePoint();
    CRTProtocol::SPoint corner2 = generatePoint();
    CRTProtocol::SPoint corner3 = generatePoint();
    CRTProtocol::SPoint corner4 = generatePoint();

    protocol.SetForceSettings(plateID, &corner1, &corner2, &corner3, &corner4);
    break;
  }

  case 13: {
    unsigned int cameraID = fdp.ConsumeIntegral<unsigned int>();
    bool enable = fdp.ConsumeBool();
    CRTPacket::EImageFormat format = static_cast<CRTPacket::EImageFormat>(
        fdp.ConsumeIntegralInRange<int>(0, 3));
    unsigned int width = fdp.ConsumeIntegral<unsigned int>();
    unsigned int height = fdp.ConsumeIntegral<unsigned int>();
    float leftCrop = fdp.ConsumeFloatingPoint<float>();
    float topCrop = fdp.ConsumeFloatingPoint<float>();
    float rightCrop = fdp.ConsumeFloatingPoint<float>();
    float bottomCrop = fdp.ConsumeFloatingPoint<float>();

    protocol.SetImageSettings(cameraID, &enable, &format, &width, &height,
                              &leftCrop, &topCrop, &rightCrop, &bottomCrop);
    break;
  }

  case 14: {
    unsigned int cameraID = fdp.ConsumeIntegral<unsigned int>();
    bool enable = fdp.ConsumeBool();

    protocol.SetCameraAutoWhiteBalance(cameraID, enable);
    break;
  }

  case 15: {
    unsigned int cameraID = fdp.ConsumeIntegral<unsigned int>();
    bool autoExposure = fdp.ConsumeBool();
    float compensation = fdp.ConsumeFloatingPoint<float>();

    protocol.SetCameraAutoExposureSettings(cameraID, autoExposure,
                                           compensation);
    break;
  }

  case 16: {
    unsigned int cameraID = fdp.ConsumeIntegral<unsigned int>();
    float focus = fdp.ConsumeFloatingPoint<float>();
    float aperture = fdp.ConsumeFloatingPoint<float>();

    protocol.SetCameraLensControlSettings(cameraID, focus, aperture);
    break;
  }

  case 17: {
    unsigned int cameraID = fdp.ConsumeIntegral<unsigned int>();
    unsigned int portNumber = fdp.ConsumeIntegral<unsigned int>();
    CRTProtocol::ESyncOutFreqMode syncOutMode =
        static_cast<CRTProtocol::ESyncOutFreqMode>(
            fdp.ConsumeIntegralInRange<int>(1, 6));
    unsigned int syncOutValue = fdp.ConsumeIntegral<unsigned int>();
    float syncOutDutyCycle = fdp.ConsumeFloatingPoint<float>();
    bool syncOutNegativePolarity = fdp.ConsumeBool();

    protocol.SetCameraSyncOutSettings(cameraID, portNumber, &syncOutMode,
                                      &syncOutValue, &syncOutDutyCycle,
                                      &syncOutNegativePolarity);
    protocol.ReadGeneralSettings();
    break;
  }

  case 18: {
    unsigned int cameraID = fdp.ConsumeIntegral<unsigned int>();
    CRTProtocol::EVideoResolution videoResolution =
        static_cast<CRTProtocol::EVideoResolution>(
            fdp.ConsumeIntegralInRange<int>(0, 4));
    CRTProtocol::EVideoAspectRatio videoAspectRatio =
        static_cast<CRTProtocol::EVideoAspectRatio>(
            fdp.ConsumeIntegralInRange<int>(0, 3));
    unsigned int videoFrequency = fdp.ConsumeIntegral<unsigned int>();
    float videoExposure = fdp.ConsumeFloatingPoint<float>();
    float videoFlashTime = fdp.ConsumeFloatingPoint<float>();

    protocol.SetCameraVideoSettings(cameraID, &videoResolution,
                                    &videoAspectRatio, &videoFrequency,
                                    &videoExposure, &videoFlashTime);
    break;
  }
  case 19: {
    std::vector<CRTProtocol::SDegreeOfFreedom> degreesOfFreedom;
    size_t numDOFs = fdp.ConsumeIntegralInRange<size_t>(0, 100);

    for (size_t i = 0; i < numDOFs; i++) {
      CRTProtocol::SDegreeOfFreedom dof;
      dof.type = generateDOF();
      dof.lowerBound = generateDouble();
      dof.upperBound = generateDouble();

      size_t numCouplings = fdp.ConsumeIntegralInRange<size_t>(0, 16);
      for (size_t j = 0; j < numCouplings; j++) {
        CRTProtocol::SCoupling coupling;
        coupling.segment = generateString();
        coupling.degreeOfFreedom = generateDOF();
        coupling.coefficient = generateDouble();
        dof.couplings.push_back(coupling);
      }

      dof.goalValue = generateDouble();
      dof.goalWeight = generateDouble();

      degreesOfFreedom.push_back(dof);
    }

    CMarkup xml;
    xml.AddElem("QTM_Settings");
    xml.IntoElem();
    xml.AddElem("Skeleton");

    std::string element = "Skeleton";
    // NOTE: We need to make this one public -> needs code modification.
    // protocol.ReadXMLDegreesOfFreedom(xml, element, degreesOfFreedom);
    break;
  }
  case 20: {
    CRTProtocol::SSettingsGeneralExternalTimestamp timestamp;
    timestamp.bEnabled = fdp.ConsumeBool();
    timestamp.nFrequency = fdp.ConsumeIntegral<unsigned int>();
    timestamp.nType = static_cast<CRTProtocol::ETimestampType>(
        fdp.ConsumeIntegralInRange<int>(0, 2));
    protocol.SetExtTimestampSettings(timestamp);
    break;
  }
  case 21: {
    bool enabled = fdp.ConsumeBool();
    auto signalSource = static_cast<CRTProtocol::ESignalSource>(
        fdp.ConsumeIntegralInRange<int>(0, 4));
    bool signalMode = fdp.ConsumeBool();
    unsigned int freqMult = fdp.ConsumeIntegral<unsigned int>();
    unsigned int freqDiv = fdp.ConsumeIntegral<unsigned int>();
    unsigned int tolerance = fdp.ConsumeIntegral<unsigned int>();
    float nominalFreq = fdp.ConsumeFloatingPoint<float>();
    bool negEdge = fdp.ConsumeBool();
    unsigned int shutterDelay = fdp.ConsumeIntegral<unsigned int>();
    float timeout = fdp.ConsumeFloatingPoint<float>();

    protocol.SetExtTimeBaseSettings(
        &enabled, &signalSource, &signalMode, &freqMult, &freqDiv, &tolerance,
        &nominalFreq, &negEdge, &shutterDelay, &timeout);
    break;
  }
  case 22: {
    unsigned int cameraID = fdp.ConsumeIntegral<unsigned int>();
    CRTProtocol::ECameraMode cam_mode = static_cast<CRTProtocol::ECameraMode>(
        fdp.ConsumeIntegralInRange<int>(0, 2));
    float pfMarkExp = generateBoundedFloat(0.0f, 100.0f);
    float pfMarkThres = generateBoundedFloat(0.0f, 1000.0f);
    int pnO = fdp.ConsumeIntegral<int>();
    protocol.SetCameraSettings(cameraID, &cam_mode, &pfMarkExp, &pfMarkThres,
                               &pnO);
    break;
  }
  }

  protocol.ReadGeneralSettings();

  bool b = fdp.ConsumeBool();
  protocol.Read3DSettings(b);
  protocol.Read6DOFSettings(b);
  protocol.ReadGazeVectorSettings(b);
  protocol.ReadEyeTrackerSettings(b);
  protocol.ReadAnalogSettings(b);
  protocol.ReadForceSettings(b);
  protocol.ReadImageSettings(b);
  protocol.ReadSkeletonSettings(b, fdp.ConsumeBool());
  protocol.ReadCalibrationSettings();

  return 0;
}
