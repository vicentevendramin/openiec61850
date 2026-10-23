<?xml version="1.0" encoding="UTF-8"?>
<!-- Ed.2.1 SCD with two IEDs written for the openiec61850 tests. -->
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="station" version="1" revision="0" toolID="handwritten">
    <History><Hitem version="1" revision="0" when="2026-01-01" what="created"/></History>
  </Header>
  <Communication>
    <SubNetwork name="StationBus" type="8-MMS" desc="Station LAN">
      <ConnectedAP iedName="IED1" apName="S1">
        <Address>
          <P type="IP">172.16.1.1</P>
          <P type="OSI-AP-Title">1 3 9999 1</P>
          <P type="OSI-AE-Qualifier">1</P>
          <P type="OSI-PSEL">00000001</P>
          <P type="OSI-SSEL">0001</P>
          <P type="OSI-TSEL">0001</P>
        </Address>
        <GSE ldInst="LD0" cbName="gcb1">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-10</P>
            <P type="APPID">0010</P>
          </Address>
        </GSE>
      </ConnectedAP>
      <ConnectedAP iedName="IED2" apName="S1">
        <Address>
          <P type="IP">172.16.1.2</P>
        </Address>
      </ConnectedAP>
    </SubNetwork>
    <SubNetwork name="Maintenance" type="8-MMS">
      <ConnectedAP iedName="IED2" apName="S2">
        <Address><P type="IP">192.168.100.2</P></Address>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="IED1" manufacturer="A">
    <AccessPoint name="S1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_S">
            <DataSet name="ds1">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" fc="ST"/>
              <FCDA ldInst="LD1" lnClass="GGIO" lnInst="2" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
            <GSEControl name="gcb1" datSet="ds1" appID="IED1_GOOSE" confRev="1"/>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_S"/>
        </LDevice>
        <LDevice inst="LD1">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_S"/>
          <LN lnClass="GGIO" inst="2" lnType="GGIO_S"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <IED name="IED2" manufacturer="B">
    <AccessPoint name="S1">
      <Server>
        <LDevice inst="CTRL">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_S"/>
          <LN lnClass="GGIO" inst="1" lnType="GGIO_S">
            <DOI name="Ind1"><DAI name="stVal"><Val>1</Val></DAI></DOI>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
    <AccessPoint name="S2">
      <ServerAt apName="S1"/>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_S" lnClass="LLN0">
      <DO name="Beh" type="ENS_S"/>
    </LNodeType>
    <LNodeType id="GGIO_S" lnClass="GGIO">
      <DO name="Beh" type="ENS_S"/>
      <DO name="Ind1" type="SPS_S"/>
    </LNodeType>
    <DOType id="ENS_S" cdc="ENS">
      <DA name="stVal" bType="Enum" type="BehKind" fc="ST" dchg="true"><Val>on</Val></DA>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>
    <DOType id="SPS_S" cdc="SPS">
      <DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"><Val>false</Val></DA>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>
    <EnumType id="BehKind">
      <EnumVal ord="1">on</EnumVal>
      <EnumVal ord="5">off</EnumVal>
    </EnumType>
  </DataTypeTemplates>
</SCL>
